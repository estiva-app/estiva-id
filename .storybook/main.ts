/**
 * Estiva ID's own Storybook (UIG-36).
 *
 * Until 2026-09-23 these stories were only visible inside Peek's Storybook,
 * which reached across into this repo. Katerina ruled that each app shows its
 * own, and that the suite-wide view is Storybook composition (UIG-19), which
 * can only show a Storybook that exists. So this is that Storybook, and Peek's
 * no longer loads these files.
 *
 * Peek uses :6006, Ship :6007 and estiva-ui :6008; this one is :6009 (the
 * `storybook` script).
 */
import type { StorybookConfig } from '@storybook/react-vite'

const config: StorybookConfig = {
  stories: ['../web/src/**/*.stories.@(ts|tsx)'],
  addons: ['@storybook/addon-docs'],
  framework: '@storybook/react-vite',
  // The app's `vite.config.ts` proxies the API to the Hono process for
  // `pnpm dev:web`. A story never reaches that server — the harness answers
  // every request itself — so the proxy is dropped here rather than left to
  // fail against a port nothing is listening on.
  viteFinal: (viteConfig) => ({
    ...viteConfig,
    server: { ...viteConfig.server, proxy: undefined },
  }),
}

export default config
