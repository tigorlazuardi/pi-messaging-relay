// @ts-check
import { defineConfig } from 'astro/config';
import starlight from '@astrojs/starlight';
import starlightLlmsTxt from 'starlight-llms-txt';
import mermaid from 'astro-mermaid';
import { pluginLineNumbers } from '@expressive-code/plugin-line-numbers';

export default defineConfig({
  site: 'https://tigorlazuardi.github.io',
  base: '/pi-messaging-relay',
  integrations: [
    mermaid({ theme: 'neutral', autoTheme: true }),
    starlight({
      title: 'Pi Messaging Relay docs',
      customCss: ['./src/styles/print.css'],
      expressiveCode: {
        plugins: [pluginLineNumbers()],
        defaultProps: { showLineNumbers: false },
      },
      components: {
        PageTitle: './src/components/PageTitle.astro',
      },
      plugins: [
        starlightLlmsTxt({
          demote: ['developer/reports/**'],
          customSets: [
            {
              label: 'User guides',
              description: 'Deployment, setup, configuration, usage, security, and troubleshooting.',
              paths: ['user/**'],
            },
            {
              label: 'Developer docs',
              description: 'Architecture, protocol, internals, decisions, and engineering reports.',
              paths: ['developer/**'],
            },
            {
              label: 'Report: Astro action Node version (2026-09)',
              description: 'GitHub Pages build fails because withastro/action v3 defaults to unsupported Node 20.',
              paths: ['developer/reports/2026-09-astro-action-node-version'],
            },
          ],
        }),
      ],
      sidebar: [
        { label: 'User guides', items: [{ autogenerate: { directory: 'user' } }] },
        { label: 'Developer docs', items: [{ autogenerate: { directory: 'developer' } }] },
      ],
    }),
  ],
});
