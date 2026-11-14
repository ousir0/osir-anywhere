import { isAbsolute, join, normalize } from 'node:path'
import z from '@deepseek-ai/schemastery'

export interface Config { osirConnectorDataDir: string }

// No account, stateRoot, Connector launcher, home lookup, or shared-root fallback.
export const Config: z<Config> = z.object({
  osirConnectorDataDir: z.string().required().description('Client 选定的 OSIR Connector 绝对数据目录。'),
})

export function connectorDataDirectory(config: Config): string {
  const directory = config?.osirConnectorDataDir
  if (typeof directory !== 'string' || !directory.trim() || directory.includes('\0') || !isAbsolute(directory)) {
    throw new Error('OSIR_DSH_ROOT_REQUIRED: osirConnectorDataDir 必须是非空绝对路径。')
  }
  return normalize(directory)
}

export function bridgeDirectory(config: Config): string {
  return join(connectorDataDirectory(config), 'dsh-bridge')
}

export function legacyBridgeDirectory(_config: Config): undefined { return undefined }
