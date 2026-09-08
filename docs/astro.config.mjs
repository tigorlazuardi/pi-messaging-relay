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
