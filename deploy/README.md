# VIT Open Project Allocation, Vercel deploy

A single static page (`index.html`). No build step, no dependencies.

## Deploy in two commands

Open PowerShell in this folder and run:

```powershell
cd "C:\Users\Aryansh Sinha\vit-open-project\deploy"
vercel login      # one time, opens your browser to sign in
vercel --prod     # deploys and prints your live URL
```

The Vercel CLI (version 56+) is already installed globally on this machine.

## What the prompts ask

`vercel --prod` will ask a few setup questions the first time:

* Set up and deploy? , yes
* Which scope? , pick your account
* Link to existing project? , no
* Project name? , press Enter to accept `deploy`, or type something like `vit-team-former`
* In which directory is your code located? , press Enter for `./`

After that it uploads and gives you a `https://your-project.vercel.app` URL. Every later `vercel --prod` from this folder updates the same site.

## Updating the page later

The live page is a copy of the tool in `index.html`. If you change the tool,
replace `index.html` in this folder and run `vercel --prod` again.
