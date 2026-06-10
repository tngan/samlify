# Background

No prior knowledge is required to use this module. Skip this chapter if you are already familiar with Single Sign-On. Otherwise, the following is a short primer.

## What is Single Sign-On (SSO)?

SSO is an access-control strategy that lets a user authenticate once and then access multiple applications without re-entering credentials.

Consider a company that runs several internal systems. Without SSO, every user must remember one set of credentials per system, and administrators must provision accounts in each system whenever an employee joins. This approach does not scale.

With SSO, the user authenticates to a single **Identity Provider** (IdP). Each application trusts the IdP, so a successful authentication grants access to every application in the trust relationship.
