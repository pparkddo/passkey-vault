# Approving from your phone

To approve on a phone, the approval page must be served over HTTPS at a host name the phone can reach.
Passkeys only work on HTTPS (or `localhost`) and only on a host name, never a bare IP address. The
passkey is bound to that host name, so pick it once and keep it.

This guide has two paths:

- [A. Try it for an hour](#a-try-it-with-a-temporary-tunnel): a temporary Cloudflare tunnel. No
  account, no domain, nothing to install on the phone. The address changes every time, so use it only
  with throwaway secrets.
- [B. Keep using it](#b-keep-using-it): a stable HTTPS address on whatever hosting you like: a
  separate server or VPS, a PaaS, or a machine at home.

For `pkv` on a different machine from the server, see
[Requester on another machine](#requester-on-another-machine).

> **Security.** Running the server on the same computer, under the same account, as an AI agent is
> fine for trying it out but not for real secrets: the agent could change the server or the page. For
> real use, run the server on another machine or follow
> [same-host isolation](deployment.md#same-host-as-the-requester).

## Before you start

- Docker with Compose v2 (`docker compose version`), git, and [uv](https://docs.astral.sh/uv/).
- For path A, `cloudflared` (`brew install cloudflared`, or see
  [Cloudflare's downloads](https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/downloads/)).
- A phone whose browser and passkey provider support PRF. iPhone with Apple Passwords works (see the
  README's Compatibility section).
- Create the passkey **on the phone itself**, on the HTTPS address below. Approving by scanning a QR
  code from another device is not supported.

## A. Try it with a temporary tunnel

Tested end to end with an iPhone. Every value in angle brackets is a placeholder.

1. **Start the tunnel first**, because the server needs to know its address:

   ```sh
   cloudflared tunnel --url http://127.0.0.1:8740
   ```

   It prints an address like `https://<random-words>.trycloudflare.com`. Keep it running. If it fails
   with status 429, wait a minute and try again.

2. **Start the server with that address as its origin** (in another terminal, in the repository).
   A vault is bound to the address it was created at, so if you did the README Quick start, remove that
   vault first with `docker compose down -v`. Then:

   ```sh
   echo "PASSKEY_VAULT_ORIGIN=https://<random-words>.trycloudflare.com" > .env   # Compose reads .env
   docker compose up -d
   docker compose exec passkey-vault cat /data/setup-code
   docker compose exec passkey-vault cat /data/requester-token
   ```

3. **On the phone**, open `https://<random-words>.trycloudflare.com`, enter the setup code, create the
   passkey (Face ID; it may ask twice) and add a test secret, e.g. name `demo`, any value.

4. **On the computer**, set up `pkv` and ask for the secret with a harmless command:

   ```sh
   PKV_TOKEN=<requester-token> pkv setup --server http://127.0.0.1:8741
   pkv run demo -c 'echo "got ${#PKV_SECRET} characters"'
   ```

   `pkv` prints an approval link with the tunnel address. Open it on the phone, check the command and
   approve. `pkv` prints `got N characters`.

5. **Clean up**: stop the tunnel (Ctrl-C), run `docker compose down -v` (this deletes the test vault),
   delete `.env`, and delete the `trycloudflare.com` passkey from the phone's password manager.

The next tunnel has a different address. The old passkey cannot open a vault at a new address, so
always start over with `docker compose down -v`.

## B. Keep using it

Run the server anywhere that gives it a **stable HTTPS address** and forwards that address to the
approver door (port 8740). The server is the same Docker image or Python package everywhere.

| Where | How the HTTPS address is made |
|---|---|
| A separate server or VPS (any cloud or hosting provider) | point a DNS name at it and put a reverse proxy in front of port 8740, e.g. Caddy, which gets the certificate itself: `caddy reverse-proxy --from vault.<your-domain> --to 127.0.0.1:8740` |
| A PaaS that runs containers | the platform terminates HTTPS; route the public address to port 8740 and give the server a persistent volume for `/data` |
| A machine at home or in the office | a tunnel that needs no open ports (for example a named Cloudflare tunnel to `http://127.0.0.1:8740`), or port forwarding plus a reverse proxy |

Whichever you choose:

1. Pick the address once (for example `vault.<your-domain>`). Passkeys are bound to it.
2. Keep the origin in `.env`, so that every `docker compose up` (after an update, a restart) uses it, and
   remove any earlier vault first (`docker compose down -v`):

   ```sh
   echo "PASSKEY_VAULT_ORIGIN=https://vault.<your-domain>" > .env
   docker compose up -d
   docker compose exec passkey-vault cat /data/setup-code
   docker compose exec passkey-vault cat /data/requester-token
   ```

   Without Docker: `passkey-vault --origin https://vault.<your-domain> --data-dir <dir>` (see
   [deployment](deployment.md#run-without-docker)).
3. Continue with steps 3 and 4 of path A: create the passkey on the phone at `https://vault.<your-domain>`,
   add your secrets, set up `pkv`. Register a second passkey (for example a security key) as a backup.

Keep in mind:

- Forward only to port 8740. The requester door (8741) is for `pkv`, never for the public address.
- Serve nothing else on that host name: every page on it can ask your passkey for its PRF output.
- Whoever controls the proxy, the hosting account or the DNS name can change the page your phone loads.
  Keep those out of your agent's reach (do not give it the hosting or DNS credentials).
- A separate server from the machine your agent runs on is the simplest way to meet the
  [deployment requirement](threat-model.md#deployment-requirement).

## Requester on another machine

When `pkv` runs on a different machine from the server:

1. On the server, open the requester door to your private network and accept the address that machine
   will use. Add to `.env` (keep the `PASSKEY_VAULT_ORIGIN` line) and restart:

   ```sh
   cat >> .env <<'EOF'
   PASSKEY_VAULT_REQUESTER_PUBLISH=0.0.0.0
   PASSKEY_VAULT_REQUESTER_HOSTS=<server-lan-ip>
   EOF
   docker compose up -d
   ```

   `0.0.0.0` publishes the requester door on every interface of the server, including loopback, so
   `pkv` on the server itself keeps working at `http://127.0.0.1:8741`. Requests still need the token,
   but only do this on a network you trust (or put the server's firewall in front). The approver door
   stays on loopback for the tunnel.

2. On the other machine, install `pkv` (`uv tool install passkey-vault-client`). Copy the requester
   token from the server (`docker compose exec passkey-vault cat /data/requester-token`) and run there:

   ```sh
   PKV_TOKEN=<requester-token> pkv setup --server http://<server-lan-ip>:8741
   ```

`pkv` always talks to the **requester door** (port 8741), never to the approval address.

## Changing the address later

A vault is bound to the address it was created at. If the server starts with a different origin, it
stops with `vault RP ID (...) differs from configured RP ID (...)`. Either keep the old origin, or start
over with an empty vault (`docker compose down -v` deletes it) and register your secrets again.
