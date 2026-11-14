"""OSIR product provider; upstream CodexProvider remains unchanged."""
from __future__ import annotations

import time

from connector.runtime_protocol import (
    RuntimeConfig,
    RuntimeConfigSchema,
    RuntimeInvalidRequestError,
    RuntimeResourceClaim,
    RuntimeSourceKey,
    RuntimeTypeDescriptor,
)
from connector.runtime_protocol.filesystem import filesystem_resource_key
from connector.runtime_protocol.host import runtime_kv_store
from connector.runtimes.codex import provider_config
from connector.runtimes.codex.osir_binding import (
    LocalCodexBinding,
    ModelBindingUnavailable,
)
from connector.runtimes.codex.osir_bound_client import BoundCodexClient
from connector.runtimes.codex.osir_bound_runtime import BoundCodexRuntime, GuardedHost
from connector.runtimes.codex.provider import CodexProvider
from connector.runtimes.codex.sdk.client import sdk_client_from_config

_REVISION = 9
_generation = 0
_FIXED = {"useSystemCodex": False, "ipcEnabled": False, "ipcDeeplinkHandoff": False,
    "environment": {}, "customModels": []}


class BoundCodexProvider(CodexProvider):
    def __init__(self, *, binding_factory=None, sdk_checker=None, sdk_client_factory=None,
                 policy_valid=True):
        super().__init__(sdk_checker=sdk_checker)
        self._binding_factory = binding_factory or LocalCodexBinding.for_product
        self._bound_sdk_factory = sdk_client_factory or sdk_client_from_config
        self._policy_valid = policy_valid

    def _reader(self):
        if not self._policy_valid:
            raise ModelBindingUnavailable()
        # A new pin for every new runtime, never a Provider-wide permanent pin.
        return self._binding_factory()

    async def discover(self):
        available = False
        try:
            await self._reader().check()
            available = bool(self._sdk_checker().get("available"))
        except (ModelBindingUnavailable, OSError, ValueError, ImportError):
            pass
        return RuntimeTypeDescriptor(runtime_type="codex", display_name="Codex",
            description="使用 OSIR 客户端当前模型；此连接不接管其他 Codex 应用。",
            available=available, recommended=True, recommendation_rank=10,
            reason=None if available else str(ModelBindingUnavailable()),
            capabilities=provider_config.codex_capabilities(),
            config_schema=await self.get_config_schema(), instance_policy="single", max_instances=1,
            metadata={"modelBinding": "osir-client", "externalCodexControl": False})

    async def get_config_schema(self):
        return RuntimeConfigSchema(runtime="codex", revision=_REVISION, schema={
            "type": "object", "additionalProperties": False,
            "properties": {
                "useSystemCodex": {"const": False}, "ipcEnabled": {"const": False},
                "ipcDeeplinkHandoff": {"const": False},
                "environment": {"type": "object", "maxProperties": 0},
                "customModels": {"type": "array", "maxItems": 0},
            }}, defaults=dict(_FIXED),
            ui_schema={"order": []})

    def _values(self, values, binding):
        raw = dict(values)
        if set(raw) - set(_FIXED):
            raise RuntimeInvalidRequestError("此连接的模型配置由本机 OSIR 客户端管理。")
        for key, value in _FIXED.items():
            if key in raw and (type(raw[key]) is not type(value) or raw[key] != value):
                raise RuntimeInvalidRequestError("此连接不接受模型路由、环境或外部 Codex 接管覆盖。")
        return {**_FIXED, "environment": {}, "customModels": []}

    async def validate_config(self, values):
        binding = await self._reader().check()
        if not self._sdk_checker().get("available"):
            raise ModelBindingUnavailable()
        schema = await self.get_config_schema()
        return RuntimeConfig(runtime="codex", revision=_REVISION,
            values=self._values(values, binding), schema=schema.schema, ui_schema=schema.ui_schema,
            metadata={"modelBinding": "osir-client"})

    async def create_runtime(self, config, host):
        global _generation
        reader = self._reader()
        binding = await reader.check()
        values = self._values(config.values, binding)
        if not self._sdk_checker().get("available"):
            raise ModelBindingUnavailable()
        store = runtime_kv_store(host)
        previous = store.get("osir-bound-generation") or {}
        _generation = max(_generation + 1, int(time.time() * 1000),
            int(previous.get("value", 0)) + 1)
        store.set("osir-bound-generation", {"value": _generation})
        # Neither caller-supplied schema/metadata nor native binding data is
        # allowed into the public config. SDK home stays in this private copy.
        schema = await self.get_config_schema()
        public = RuntimeConfig(runtime="codex", revision=_generation, values=values,
            schema=schema.schema, ui_schema=schema.ui_schema,
            metadata={"modelBinding": "osir-client", "externalCodexControl": False})
        native = RuntimeConfig(runtime="codex", revision=_generation,
            values={**values, "codexHome": str(binding.home)})
        client = BoundCodexClient(self._bound_sdk_factory(native, local_binding=binding), reader, store)

        async def guard():
            await runtime._guard()

        protected_host = GuardedHost(host, guard)
        runtime = BoundCodexRuntime(config=native, host=protected_host, client=client,
            client_message_kv=store, ipc_enabled=False, ipc_deeplink_handoff=False,
            safe_ipc_write_routing=True)
        runtime.public_config = public
        return runtime

    def resource_claims(self, config):
        binding = self._reader().read()
        self._values(config.values, binding)
        return (RuntimeResourceClaim(kind="codex_home",
            key=filesystem_resource_key(str(binding.home)), label="OSIR Client Codex Home"),)

    def session_source_key(self, config):
        binding = self._reader().read()
        self._values(config.values, binding)
        return RuntimeSourceKey(kind="codex_home", key=filesystem_resource_key(str(binding.home)),
            local_only=True)
