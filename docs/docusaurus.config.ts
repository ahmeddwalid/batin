import { themes as prismThemes } from 'prism-react-renderer';
import type { Config } from '@docusaurus/types';
import type * as Preset from '@docusaurus/preset-classic';

const config: Config = {
  title: 'Batin',
  tagline: 'Security-Hardened File Type Detection',
  favicon: 'img/favicon.ico',

  // Production URL (custom domain served via GitHub Pages)
  url: 'https://batin.ahmeddwalid.me',
  baseUrl: '/',

  // GitHub Pages deployment config
  organizationName: 'ahmeddwalid',
  projectName: 'batin',
  deploymentBranch: 'gh-pages',
  trailingSlash: false,

  onBrokenLinks: 'throw',
  onBrokenMarkdownLinks: 'warn',

  // i18n configuration
  i18n: {
    defaultLocale: 'en',
    locales: ['en', 'ar'],
    localeConfigs: {
      en: {
        htmlLang: 'en-US',
        label: 'English',
        direction: 'ltr',
      },
      ar: {
        htmlLang: 'ar',
        label: 'العربية',
        direction: 'rtl',
      },
    },
  },

  // Mermaid support
  markdown: {
    mermaid: true,
  },
  themes: [
    '@docusaurus/theme-mermaid',
    [
      '@easyops-cn/docusaurus-search-local',
      {
        // Index docs and pages
        indexDocs: true,
        indexPages: true,
        indexBlog: false,
        // Language support
        language: ['en', 'ar'],
        // Search bar position
        searchBarPosition: 'right',
        // Highlight search results
        highlightSearchTermsOnTargetPage: true,
        // Remove default Algolia search
        removeDefaultStopWordFilter: true,
        // Search result limit
        searchResultLimits: 10,
        // Search context
        searchContextByPaths: ['docs'],
        // Hide search bar in small screens
        hideSearchBarWithNoSearchContext: false,
        // Use all context for search
        useAllContextsWithNoSearchContext: true,
      },
    ],
  ],

  presets: [
    [
      'classic',
      {
        docs: {
          sidebarPath: './sidebars.ts',
          editUrl: 'https://github.com/ahmeddwalid/batin/tree/main/docs/',
        },
        blog: false, // Disable blog
        theme: {
          customCss: './src/css/custom.css',
        },
      } satisfies Preset.Options,
    ],
  ],

  themeConfig: {
    // Social card
    image: 'img/social-card.png',

    // Color mode configuration
    colorMode: {
      defaultMode: 'dark',
      disableSwitch: false,
      respectPrefersColorScheme: true,
    },

    // Navbar
    navbar: {
      title: 'Batin',
      logo: {
        alt: 'Batin Logo',
        src: 'img/logo.svg',
      },
      items: [
        {
          type: 'docSidebar',
          sidebarId: 'userSidebar',
          position: 'left',
          label: 'User Guide',
        },
        {
          type: 'docSidebar',
          sidebarId: 'developerSidebar',
          position: 'left',
          label: 'Developer Docs',
        },
        {
          type: 'localeDropdown',
          position: 'right',
        },
        {
          href: 'https://github.com/ahmeddwalid/batin',
          label: 'GitHub',
          position: 'right',
        },
      ],
    },

    // Footer
    footer: {
      style: 'dark',
      links: [
        {
          title: 'Documentation',
          items: [
            {
              label: 'User Guide',
              to: '/docs/user/intro',
            },
            {
              label: 'Developer Docs',
              to: '/docs/developer/architecture',
            },
          ],
        },
        {
          title: 'Community',
          items: [
            {
              label: 'GitHub Discussions',
              href: 'https://github.com/ahmeddwalid/batin/discussions',
            },
            {
              label: 'Issues',
              href: 'https://github.com/ahmeddwalid/batin/issues',
            },
          ],
        },
        {
          title: 'More',
          items: [
            {
              label: 'GitHub',
              href: 'https://github.com/ahmeddwalid/batin',
            },
            {
              label: 'Crates.io',
              href: 'https://crates.io/crates/batin',
            },
          ],
        },
      ],
      copyright: `Copyright © ${new Date().getFullYear()} Ahmed Walid. Built with Docusaurus.`,
    },

    // Prism syntax highlighting
    prism: {
      theme: prismThemes.github,
      darkTheme: prismThemes.dracula,
      additionalLanguages: ['rust', 'toml', 'bash', 'json'],
    },

    // Mermaid theme
    mermaid: {
      theme: { light: 'default', dark: 'dark' },
    },

    // Algolia DocSearch - Primary search (requires deployed site to be indexed)
    algolia: {
      appId: '06GI172TDC',
      apiKey: 'd6fa6a4d58342dbf27f99af1088ad344',
      indexName: 'batin',
      contextualSearch: true,
      searchParameters: {},
      searchPagePath: 'search',
    },
    // Note: Local search (@easyops-cn/docusaurus-search-local) is also enabled
    // in the themes array as a fallback for development/offline use
  } satisfies Preset.ThemeConfig,
};

export default config;
