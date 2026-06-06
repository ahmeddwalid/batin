import type { SidebarsConfig } from '@docusaurus/plugin-content-docs';

const sidebars: SidebarsConfig = {
  // User documentation sidebar
  userSidebar: [
    {
      type: 'category',
      label: 'Getting Started',
      collapsed: false,
      items: [
        'user/intro',
        'user/installation',
        'user/quickstart',
      ],
    },
    {
      type: 'category',
      label: 'CLI Reference',
      items: [
        'user/cli-reference',
        'user/output-formats',
      ],
    },
    {
      type: 'category',
      label: 'Use Cases',
      items: [
        'user/use-cases',
        'user/malware-analysis',
        'user/digital-forensics',
      ],
    },
    {
      type: 'category',
      label: 'Extending & Integrating',
      items: [
        'user/custom-signatures',
        'user/yara',
        'user/integrations',
      ],
    },
    {
      type: 'category',
      label: 'Configuration',
      items: [
        'user/configuration',
        'user/threat-levels',
        'user/threat-model',
      ],
    },
  ],

  // Developer documentation sidebar
  developerSidebar: [
    {
      type: 'category',
      label: 'Architecture',
      collapsed: false,
      items: [
        'developer/architecture',
        'developer/detection-pipeline',
        'developer/module-structure',
      ],
    },
    {
      type: 'category',
      label: 'Core Concepts',
      items: [
        'developer/concepts/magic-bytes',
        'developer/concepts/entropy-analysis',
        'developer/concepts/polyglot-detection',
        'developer/concepts/embedded-threats',
        'developer/concepts/threat-assessment',
      ],
    },
    {
      type: 'category',
      label: 'Module Deep Dives',
      items: [
        'developer/modules/signatures',
        'developer/modules/entropy',
        'developer/modules/polyglot',
        'developer/modules/embedded',
        'developer/modules/validation',
        'developer/modules/archive',
        'developer/modules/batch',
      ],
    },
    {
      type: 'category',
      label: 'API Reference',
      items: [
        'developer/api/file-type',
        'developer/api/detection-config',
        'developer/api/entropy-profile',
        'developer/api/threat-types',
      ],
    },
    {
      type: 'category',
      label: 'Contributing',
      items: [
        'developer/contributing',
        'developer/testing',
        'developer/fuzzing',
      ],
    },
  ],
};

export default sidebars;
