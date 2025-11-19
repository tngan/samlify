import { defineConfig } from 'vitepress'

export default defineConfig({
  title: 'samlify',
  description: 'Nodejs library for Single Sign On with SAML 2.0',
  base: '/',
  ignoreDeadLinks: 'localhostLinks',
  
  head: [
    ['link', { rel: 'icon', href: '/favicon.ico' }]
  ],

  themeConfig: {
    logo: '/padlock.png',
    
    nav: [
      { text: 'Home', link: '/' },
      { text: 'Get Started', link: '/prerequistite' },
      { text: 'GitHub', link: 'https://github.com/tngan/samlify' }
    ],

    sidebar: [
      {
        text: 'Get Started',
        items: [
          { text: 'Prerequisite', link: '/prerequistite' }
        ]
      },
      {
        text: 'Basic',
        items: [
          { text: 'Introduction', link: '/basic' },
          { text: 'Identity Provider', link: '/idp' },
          { text: 'Service Provider', link: '/sp' },
          {
            text: 'SAML Request',
            items: [
              { text: 'SAML Request', link: '/saml-request' },
              { text: 'Signed', link: '/signed-saml-request' }
            ]
          },
          {
            text: 'SAML Response',
            items: [
              { text: 'SAML Response', link: '/saml-response' },
              { text: 'Signed', link: '/signed-saml-response' },
              { text: 'Encrypted', link: '/encrypted-saml-response' }
            ]
          },
          { text: 'Key Generation', link: '/key-generation' }
        ]
      },
      {
        text: 'Advanced',
        items: [
          { text: 'Introduction', link: '/advance' },
          { text: 'Metadata Distribution', link: '/metadata-distribution' },
          {
            text: 'IDP/SP Configuration',
            items: [
              { text: 'Configuration', link: '/configuration' },
              { text: 'Identity Provider', link: '/idp-configuration' },
              { text: 'Service Provider', link: '/sp-configuration' }
            ]
          },
          { text: 'Attributes & Template', link: '/template' },
          { text: 'Multiple Entities', link: '/multi-entities' }
        ]
      },
      {
        text: 'Examples',
        items: [
          { text: 'Gitlab', link: '/gitlab' },
          { text: 'OneLogin', link: '/onelogin' },
          { text: 'Okta', link: '/okta' },
          { text: 'Inbound SAML', link: '/okta-inbound' }
        ]
      }
    ],

    socialLinks: [
      { icon: 'github', link: 'https://github.com/tngan/samlify' }
    ],

    search: {
      provider: 'local'
    }
  }
})
