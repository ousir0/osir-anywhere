import type { Context } from '@deepseek-ai/cordis'
import { DshRuntimeService } from './dsh-runtime/index.js'
import { Config, connectorDataDirectory } from './osir-config.js'

export { Config } from './osir-config.js'
export const name = 'osir-anywhere-dsh-bridge'

export function apply(ctx: Context, config: Config): void {
  connectorDataDirectory(config)
  if (ctx.get('agentsAnywhereRuntime', false) || ctx.get('agentsAnywhereOnboarding', false)
    || ctx.registry.get(DshRuntimeService)) {
    throw new Error('OSIR_DSH_BRIDGE_CONFLICT: 已存在 Anywhere Bridge/Onboarding；请由 Client 阻断接入并提示处理，禁止自动卸载上游插件。')
  }
  ctx.plugin(DshRuntimeService, config)
}
