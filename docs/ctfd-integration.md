# CTFd Integration Guide

This guide walks you through connecting the CTF PCAP Generator to CTFd so that challenges, PCAP files, flags, and hints are pushed automatically. Instead of manually uploading files and typing flags into CTFd, you generate a PCAP and click one button -- the generator handles the rest.

CTFd is an open-source Capture The Flag platform where students log in, download challenge files, and submit flags to earn points. If you have never used CTFd before, this guide assumes no prior knowledge and explains every step.

Before you begin, make sure the PCAP generator itself is installed and running. If you have not done that yet, start with the [Deployment Guide](./deployment.md) and come back here once you can open http://localhost:5000 in your browser.

---

## Which Path Do You Need?

- **Already have a CTFd instance running?** Jump straight to [Quick Connect](#quick-connect) -- you just need your CTFd URL and an API token.
- **Starting from scratch?** Begin with [Full Setup From Scratch](#full-setup-from-scratch) to get CTFd running alongside the PCAP generator, then continue to [Quick Connect](#quick-connect).

---

## Full Setup From Scratch

This section walks you through installing and running CTFd using Docker Compose. CTFd will run as a separate project from the PCAP generator -- each gets its own terminal and its own port.

**Important port distinction:** The PCAP generator runs on **port 5000**. CTFd runs on **port 8000**. These are two separate applications that happen to both use Docker. They do not conflict because they listen on different ports.

### Step 1: Open a New Terminal

Leave the PCAP generator running in its current terminal. Open a second terminal window -- this one is for CTFd.

### Step 2: Clone the CTFd Repository

```bash
git clone https://github.com/CTFd/CTFd.git
cd CTFd
```

### Step 3: Start CTFd

```bash
docker compose up
```

This starts four services: the CTFd application, a database (MariaDB), a cache (Redis), and an nginx reverse proxy. The first startup takes 1-2 minutes while Docker downloads images and initializes the database.

### Step 4: Run the Setup Wizard

Open [http://localhost:8000](http://localhost:8000) in your browser. You will see the CTFd first-time setup wizard.

1. Create an admin account -- choose a username, email address, and password. This is the account you will use to manage challenges.
2. Set basic CTF settings -- give your competition a name and description. You can change these later.
3. Click through to finish the setup.

You now have a running CTFd instance. Keep this terminal open -- CTFd needs to stay running while you use it.

> **Tip:** Both the PCAP generator (port 5000) and CTFd (port 8000) can run at the same time on the same machine with no conflicts. They are separate Docker Compose projects in separate directories.

---

## Generating an API Token

An API token is a secret key that lets the PCAP generator talk to CTFd on your behalf, without needing your username and password. You generate one inside CTFd's admin settings and then paste it into the PCAP generator.

### Steps

1. Log into CTFd as an admin at [http://localhost:8000](http://localhost:8000).
2. Click your username in the top-right corner, then click **Settings**.
3. Click the **Access Tokens** tab.
4. Set an expiration date -- 30 days is a reasonable choice for a competition.
5. Click **Generate**.
6. **Copy the token immediately.** CTFd will not show it again after you leave this page.
7. Store the token securely -- you will paste it into the PCAP generator in the next step.

---

## Quick Connect

If you already have a CTFd instance running (whether you just set it up above or you have an existing server), follow these steps to connect the PCAP generator to it.

1. Open the PCAP generator at [http://localhost:5000](http://localhost:5000).
2. Go to the **Settings** page.
3. Enter your **CTFd URL** -- for a local setup this is `http://localhost:8000`. If your CTFd is on a remote server, enter that URL instead.
4. Enter the **API token** you generated in CTFd.
5. Click **Test Connection**. You should see a success message confirming the generator can reach your CTFd instance.
6. The connection is saved for the session.

If you want to set the CTFd URL and API token permanently so they persist across restarts, you can add them to your `.env` file:

```env
CTFD_URL=http://localhost:8000
CTFD_TOKEN=your-api-token-here
```

See the [Configuration Reference](./configuration.md) for details on all available environment variables.

---

## Pushing a Single Challenge

This is the basic workflow: generate one PCAP and push it to CTFd as a complete challenge.

### Steps

1. In the PCAP generator (http://localhost:5000), select a scenario and difficulty level, then enter a flag string (for example, `CTF{found_the_injection}`).
2. Click **Generate** to create the PCAP file.
3. On the result page, click **Push to CTFd**.

Behind the scenes, the generator performs these steps automatically:

- Checks that no challenge with the same name already exists in CTFd
- Creates a new challenge entry with the name, description, category, and point value
- Uploads the PCAP file as a downloadable attachment
- Sets the flag so CTFd knows the correct answer
- Adds hints if the scenario includes any

A "challenge" in CTFd is a task that students see when they log in. It has a name, a description explaining what to investigate, a point value, one or more attached files (your PCAP), and a flag (the answer students must submit). When you push from the generator, all of these are created for you.

### Verify in CTFd

Switch to your CTFd instance at [http://localhost:8000](http://localhost:8000). Navigate to **Admin > Challenges**. You should see the new challenge listed with the correct name and category.

---

## Batch Pushing

If you generated a batch of challenges (multiple scenarios at once), the result page shows all of them together.

1. Review the list of generated challenges on the batch result page.
2. Click **Push All to CTFd** to push every challenge in the batch.
3. Each challenge is pushed individually using the same process described above -- duplicate check, challenge creation, file upload, flag creation, and hint creation.
4. Switch to CTFd and navigate to **Admin > Challenges** to verify all challenges appear.

Batch pushing is convenient when setting up an entire competition at once. Generate your full set of challenges, push them all, and your CTFd instance is ready for students.

---

## Troubleshooting

### "Connection refused" or "Cannot reach CTFd"

CTFd is not running or is not reachable at the URL you entered. Verify:

- Is CTFd running? Open [http://localhost:8000](http://localhost:8000) in your browser and confirm you see the CTFd interface.
- If CTFd is on a remote server, double-check the URL -- make sure you include `http://` or `https://` and the correct port.
- If you just started CTFd, wait 1-2 minutes for it to finish initializing.

### "Unauthorized" or "Invalid API token"

Your API token is expired, incorrect, or was not copied completely. To fix this:

1. Log into CTFd as an admin.
2. Go to **Settings > Access Tokens**.
3. Generate a new token.
4. Copy the full token and paste it into the PCAP generator's Settings page.
5. Click **Test Connection** to confirm it works.

### "Duplicate challenge" error

A challenge with the same name already exists in CTFd. You have two options:

- **Rename:** Generate the challenge again with a different name.
- **Delete the old one:** In CTFd, go to **Admin > Challenges**, find the duplicate, and delete it. Then push again from the PCAP generator.

### Connection works but push fails

If the test connection succeeds but pushing a challenge fails:

- Check that the PCAP file was generated successfully (you should see a download link on the result page).
- If you see a file size error, the PCAP may exceed CTFd's upload limit. Try generating with a lower difficulty (which produces fewer packets and a smaller file).
