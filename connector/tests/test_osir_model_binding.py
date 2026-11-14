import asyncio
import hashlib
import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from connector.runtimes.codex.sdk.runtime_client import (
    CodexModelListResult,
    CodexStartThreadRequest,
)
from connector.server.osir_model_binding import (
    BoundProjectCodexClient,
    LocalCodexBinding,
    ModelBindingUnavailable,
)
from connector.server.osir_project_runtime import (
    PROJECT_CONFIG,
    ProjectCatalogReader,
    ProjectCodexProvider,
    ProjectCodexRuntime,
)
from connector.server.osir_project_scope import ProjectCodexClient
from tests.test_codex_runtime import FakeCodexClient, FakeHost, _config


@pytest.fixture
def binding(tmp_path):
    root = tmp_path.resolve()
    home = root / 'codex'
    home.mkdir()
    config = b'model = "active/new"\nmodel_reasoning_effort = "medium"\nmodel_catalog_json = "catalog.json"\n# secret-sentinel-key\n'
    catalog = b'{"models":[{"slug":"retired/old"},{"slug":"active/new"}]}'
    (home / 'config.toml').write_bytes(config)
    (home / 'catalog.json').write_bytes(catalog)
    data = {'schemaVersion': 1, 'source': 'osir-client', 'available': True,
        'codexHome': str(home), 'connectionMode': 'proxy',
        'defaultModel': 'active/new', 'defaultReasoningEffort': 'medium',
        'models': [{'id': 'active/new', 'title': 'Current'}, {'id': 'active/other', 'title': 'Other'}],
        'configSha256': hashlib.sha256(config).hexdigest(),
        'catalogSha256': hashlib.sha256(catalog).hexdigest(),
        'revision': 'a' * 64, 'expiresAtMs': 1_030_000}
    path = root / 'binding.json'
    path.write_text(json.dumps(data))
    path.chmod(0o600)
    return LocalCodexBinding(path, clock=lambda: 1000), data


def write(reader, data):
    reader.path.write_text(json.dumps(data))
    reader.path.chmod(0o600)


def test_current_binding_is_non_secret_and_pins_revision(binding):
    reader, data = binding
    current = reader.read()
    assert current.default_model == 'active/new'
    assert current.select(None) == 'active/new'
    assert 'secret-sentinel' not in repr(current)
    data['expiresAtMs'] += 1000
    write(reader, data)
    assert reader.read() == current
    data['revision'] = 'b' * 64
    write(reader, data)
    with pytest.raises(ModelBindingUnavailable):
        reader.read()


@pytest.mark.parametrize('mutation', [
    lambda d: d.update(expiresAtMs=999999),
    lambda d: d.update(expiresAtMs=1036000),
    lambda d: d.update(available=False),
    lambda d: d.update(schemaVersion=True),
    lambda d: d.update(defaultModel='retired/old'),
    lambda d: d.update(defaultReasoningEffort='high'),
    lambda d: d.update(configSha256='b' * 64),
    lambda d: d.update(catalogSha256='b' * 64),
    lambda d: d.update(apiKey='secret-sentinel'),
    lambda d: d['models'].append(d['models'][0]),
    lambda d: d['models'][0].update(apiKey='secret-sentinel'),
])
def test_invalid_and_stale_bindings_fail_closed_without_secret_errors(binding, mutation):
    reader, data = binding
    mutation(data)
    write(reader, data)
    with pytest.raises(ModelBindingUnavailable) as error:
        reader.read()
    assert 'secret-sentinel' not in str(error.value)


def test_key_rotation_or_catalog_change_blocks_next_turn(binding):
    reader, _ = binding
    home = reader.read().home
    (home / 'config.toml').write_bytes(b'model = "active/new"\n# rotated-secret-sentinel')
    with pytest.raises(ModelBindingUnavailable):
        reader.read()


def test_updated_file_hash_cannot_bypass_revision_pin(binding):
    reader, data = binding
    home = reader.read().home
    config = (home / 'config.toml').read_bytes() + b'\n# rotated\n'
    (home / 'config.toml').write_bytes(config)
    data['configSha256'] = hashlib.sha256(config).hexdigest()
    write(reader, data)
    with pytest.raises(ModelBindingUnavailable):
        reader.read()


@pytest.mark.parametrize('mode', [0o644, 0o666, 0o400])
def test_descriptor_requires_private_native_owner_permissions(binding, mode):
    reader, _ = binding
    reader.path.chmod(mode)
    with pytest.raises(ModelBindingUnavailable):
        reader.read()


def test_symlink_descriptor_is_denied(binding):
    reader, _ = binding
    target = reader.path.with_suffix('.real')
    reader.path.rename(target)
    reader.path.symlink_to(target)
    with pytest.raises(ModelBindingUnavailable):
        reader.read()


def test_only_authoritative_models_are_listed_and_default_is_first(binding):
    reader, _ = binding
    delegate = SimpleNamespace(list_models=AsyncMock(return_value=CodexModelListResult(models=(
        {'id': 'retired/old', 'displayName': 'Old'},
        {'id': 'active/new', 'displayName': 'stale-name', 'apiKey': 'secret-sentinel'},
    ))))
    scope = SimpleNamespace(codex_home=reader.read().home)
    client = BoundProjectCodexClient(delegate, scope, reader)
    result = asyncio.run(client.list_models())
    assert [model['id'] for model in result.models] == ['active/new', 'active/other']
    assert result.models[0]['isDefault'] is True
    assert 'secret-sentinel' not in repr(result)


def test_default_model_is_explicit_and_retired_model_never_reaches_native(binding, monkeypatch):
    reader, _ = binding
    client = BoundProjectCodexClient(object(), SimpleNamespace(codex_home=reader.read().home), reader)
    native = AsyncMock(return_value=SimpleNamespace(thread_id='test'))
    monkeypatch.setattr(ProjectCodexClient, 'start_thread', native)
    asyncio.run(client.start_thread(CodexStartThreadRequest(cwd='/fixture')))
    assert native.await_args.args[0].model == 'active/new'
    with pytest.raises(ModelBindingUnavailable):
        asyncio.run(client.start_thread(CodexStartThreadRequest(model='retired/old')))
    assert native.await_count == 1


def test_retained_native_catalog_never_crosses_cloud_metadata_boundary(binding):
    reader, _ = binding
    delegate = SimpleNamespace(list_models=AsyncMock(return_value=CodexModelListResult(models=(
        {'id': 'active/new', 'supportedReasoningEfforts': [
            {'reasoningEffort': 'medium', 'apiKey': 'secret-sentinel'},
            {'reasoningEffort': 'high', 'description': 'secret-sentinel'}]},
    ))))
    client = BoundProjectCodexClient(delegate, SimpleNamespace(codex_home=reader.read().home), reader)
    result = asyncio.run(client.list_models())
    assert result.models[0]['supportedReasoningEfforts'] == [
        {'reasoningEffort': 'medium'}, {'reasoningEffort': 'high'}]
    assert 'secret-sentinel' not in repr(result)


def test_config_change_while_starting_closes_only_owned_native_client(binding, monkeypatch):
    reader, data = binding
    started = AsyncMock()
    stopped = AsyncMock()
    async def start(_self, _handler):
        await started()
        data['revision'] = 'b' * 64
        write(reader, data)
    monkeypatch.setattr(ProjectCodexClient, 'start', start)
    monkeypatch.setattr(ProjectCodexClient, 'stop', stopped)
    client = BoundProjectCodexClient(object(), SimpleNamespace(codex_home=reader.read().home), reader)
    with pytest.raises(ModelBindingUnavailable):
        asyncio.run(client.start(AsyncMock()))
    started.assert_awaited_once()
    stopped.assert_awaited_once()


def test_live_catalog_check_cannot_use_retained_sdk_cache(binding):
    reader, data = binding
    reader.read()
    config = _config()
    catalog = ProjectCatalogReader(config, AsyncMock(), lambda: CodexModelListResult(models=()))
    catalog.model_binding = reader
    data['available'] = False
    write(reader, data)
    with pytest.raises(ModelBindingUnavailable):
        asyncio.run(catalog.list_model_catalog())
    catalog.ensure_started.assert_not_awaited()


def test_all_selection_consumers_use_project_catalog():
    runtime = ProjectCodexRuntime(config=_config(), host=FakeHost(), client=FakeCodexClient())
    for consumer in (runtime._session_reader, runtime._turns, runtime._turns.actions,
                     runtime._turns.selections, runtime._turns.session_starter):
        assert consumer.list_model_catalog.__self__ is runtime._catalogs


def test_native_home_and_public_catalog_revision_follow_binding(binding, tmp_path, monkeypatch):
    import connector.server.osir_project_runtime as module
    from connector.runtime_protocol.instance_models import MAX_CONFIG_REVISION
    from connector.runtimes.catalog_revisions import runtime_catalog_revision

    reader, _ = binding
    scope = SimpleNamespace(codex_home=reader.read().home)
    monkeypatch.setattr(module, 'sdk_client_from_config', lambda config: FakeCodexClient())
    provider = ProjectCodexProvider(scope, tmp_path / 'state.json', reader)
    async def run():
        config = await provider.validate_config(PROJECT_CONFIG)
        runtime = await provider.create_runtime(config, FakeHost())
        assert runtime.config.values['codexHome'] == str(scope.codex_home)
        assert 8003 < runtime_catalog_revision(runtime.config.revision, 3) <= MAX_CONFIG_REVISION
        assert runtime.client.model_binding is reader
    asyncio.run(run())


def test_contract_fixture_matches_schema(binding):
    import jsonschema
    _, data = binding
    schema = json.loads((Path(__file__).resolve().parents[2] /
        'contracts/osir-local-model-binding/v1/schema.json').read_text())
    jsonschema.validate(data, schema)
