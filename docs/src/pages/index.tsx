import React from 'react';
import clsx from 'clsx';
import Link from '@docusaurus/Link';
import useDocusaurusContext from '@docusaurus/useDocusaurusContext';
import Layout from '@theme/Layout';
import Heading from '@theme/Heading';
import Translate, { translate } from '@docusaurus/Translate';

import styles from './index.module.css';

function HomepageHeader() {
  const { siteConfig } = useDocusaurusContext();
  return (
    <header className={clsx('hero hero--primary', styles.heroBanner)}>
      <div className="container">
        <Heading as="h1" className="hero__title">
          🔍 {siteConfig.title}
        </Heading>
        <p className="hero__subtitle">
          <Translate id="homepage.tagline" description="The homepage tagline">
            Security-Hardened File Type Detection
          </Translate>
        </p>
        <div className={styles.buttons}>
          <Link
            className="button button--secondary button--lg"
            to="/docs/user/intro">
            <Translate id="homepage.getStarted" description="Get started button">
              Get Started 🚀
            </Translate>
          </Link>
          <Link
            className="button button--outline button--secondary button--lg"
            style={{ marginLeft: '1rem' }}
            to="/docs/developer/architecture">
            <Translate id="homepage.developerDocs" description="Developer docs button">
              Developer Docs 📖
            </Translate>
          </Link>
        </div>
      </div>
    </header>
  );
}

function Feature({ emoji, title, description }: { emoji: string; title: React.ReactNode; description: React.ReactNode }) {
  return (
    <div className={clsx('col col--4')}>
      <div className="text--center">
        <span style={{ fontSize: '4rem' }}>{emoji}</span>
      </div>
      <div className="text--center padding-horiz--md">
        <Heading as="h3">{title}</Heading>
        <p>{description}</p>
      </div>
    </div>
  );
}

function HomepageFeatures() {
  return (
    <section className={styles.features}>
      <div className="container">
        <div className="row">
          <Feature
            emoji="🔍"
            title={<Translate id="homepage.feature.deepDetection.title">Deep Detection</Translate>}
            description={<Translate id="homepage.feature.deepDetection.description">Goes beyond file extensions. Analyzes magic bytes, entropy, and file structure to reveal true content.</Translate>}
          />
          <Feature
            emoji="🛡️"
            title={<Translate id="homepage.feature.securityFirst.title">Security First</Translate>}
            description={<Translate id="homepage.feature.securityFirst.description">Zero unsafe code. Fuzz-tested. Bounded resource usage. Built to handle any input safely.</Translate>}
          />
          <Feature
            emoji="⚡"
            title={<Translate id="homepage.feature.highPerformance.title">High Performance</Translate>}
            description={<Translate id="homepage.feature.highPerformance.description">Async I/O with Tokio. Parallel processing with Rayon. Optimized single-pass algorithms.</Translate>}
          />
          <Feature
            emoji="🎯"
            title={<Translate id="homepage.feature.threatDetection.title">Threat Detection</Translate>}
            description={<Translate id="homepage.feature.threatDetection.description">Identifies packed executables, polyglot files, embedded macros, and suspicious patterns.</Translate>}
          />
          <Feature
            emoji="📦"
            title={<Translate id="homepage.feature.easyIntegration.title">Easy Integration</Translate>}
            description={<Translate id="homepage.feature.easyIntegration.description">Use as a CLI tool, Rust library, or Docker container. JSON and CSV output for automation.</Translate>}
          />
          <Feature
            emoji="🌍"
            title={<Translate id="homepage.feature.crossPlatform.title">Cross-Platform</Translate>}
            description={<Translate id="homepage.feature.crossPlatform.description">Works on Linux, Windows, macOS, and FreeBSD. Multiple architecture support.</Translate>}
          />
        </div>
      </div>
    </section>
  );
}

function QuickStart() {
  return (
    <section className={styles.quickstart}>
      <div className="container">
        <Heading as="h2" className="text--center">
          <Translate id="homepage.quickStart.title">Quick Start</Translate>
        </Heading>
        <div className="row">
          <div className="col col--6">
            <Heading as="h3">
              <Translate id="homepage.quickStart.installViaCargo">Install via Cargo</Translate>
            </Heading>
            <pre><code>cargo install batin</code></pre>
          </div>
          <div className="col col--6">
            <Heading as="h3">
              <Translate id="homepage.quickStart.scanFile">Scan a File</Translate>
            </Heading>
            <pre><code>batin scan suspicious.exe</code></pre>
          </div>
        </div>
        <div className="row" style={{ marginTop: '2rem' }}>
          <div className="col col--12">
            <Heading as="h3">
              <Translate id="homepage.quickStart.useAsLibrary">Use as Library</Translate>
            </Heading>
            <pre><code>{`use batin::{FileType, DetectionConfig};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = DetectionConfig::default();
    let result = FileType::from_file_path("file.pdf", &config).await?;
    
    println!("Type: {} ({:?})", result.extension, result.threat_level);
    Ok(())
}`}</code></pre>
          </div>
        </div>
      </div>
    </section>
  );
}

export default function Home(): React.JSX.Element {
  const { siteConfig } = useDocusaurusContext();
  return (
    <Layout
      title={`${siteConfig.title} - Security-Hardened File Detection`}
      description="Professional file type detection with threat assessment. Detects packed executables, polyglot files, embedded macros, and more.">
      <HomepageHeader />
      <main>
        <HomepageFeatures />
        <QuickStart />
      </main>
    </Layout>
  );
}

