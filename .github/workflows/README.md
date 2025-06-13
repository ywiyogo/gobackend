# GitHub Actions Deployment Setup

This directory contains GitHub Actions workflows for automated deployment of the Go Backend application.

## 🔧 Required Secrets

To enable automated deployment, you need to configure the following secrets in your GitHub repository:

### Setting up GitHub Secrets

1. Go to your GitHub repository
2. Click on **Settings** → **Secrets and variables** → **Actions**
3. Click **New repository secret** and add each of the following:

### Required Secrets

| Secret Name | Description | Example |
|-------------|-------------|---------|
| `VPS_HOST` | Your VPS server IP address or domain | `123.456.789.0` or `yourserver.com` |
| `VPS_USER` | SSH username for your VPS | `ubuntu` or `root` |
| `VPS_SSH_KEY` | Private SSH key for server access | Contents of your `~/.ssh/id_rsa` file |
| `VPS_PROJECT_PATH` | Path to your project on the VPS | `/opt/gobackend` (optional, defaults to this) |

## 🔑 SSH Key Setup

### 1. Generate SSH Key Pair (if you don't have one)

On your local machine:
```bash
ssh-keygen -t rsa -b 4096 -C "github-actions@yourproject.com"
```

### 2. Copy Public Key to VPS

```bash
ssh-copy-id -i ~/.ssh/id_rsa.pub user@your-vps-ip
```

Or manually add the public key to your VPS:
```bash
# On your VPS
mkdir -p ~/.ssh
echo "your-public-key-content" >> ~/.ssh/authorized_keys
chmod 600 ~/.ssh/authorized_keys
chmod 700 ~/.ssh
```

### 3. Add Private Key to GitHub Secrets

```bash
# Copy the private key content
cat ~/.ssh/id_rsa
```

Copy the entire output (including `-----BEGIN OPENSSH PRIVATE KEY-----` and `-----END OPENSSH PRIVATE KEY-----`) and add it as the `VPS_SSH_KEY` secret in GitHub.

## 🚀 Deployment Workflow

The deployment workflow (`deploy.yml`) will:

1. **Trigger** on every push to the `main` branch
2. **Connect** to your VPS via SSH
3. **Pull** the latest code from GitHub
4. **Deploy** using the production deployment script
5. **Verify** deployment with health checks
6. **Notify** of success or failure

## 🔧 VPS Prerequisites

Your VPS server must have:

- **Git** installed and repository cloned
- **Docker** and **Docker Compose** installed
- **Project directory** at the specified path (default: `/opt/gobackend`)
- **Deployment configuration** ready in `deployment/production/`

### Initial VPS Setup

```bash
# On your VPS
sudo apt update
sudo apt install -y git docker.io docker-compose

# Clone your repository
cd /opt
sudo git clone https://github.com/yourusername/gobackend.git
sudo chown -R $USER:$USER gobackend

# Setup deployment configuration
cd gobackend/deployment/production
cp .env.example .env
# Edit .env with your production values
nano .env

# Make deployment script executable
chmod +x deploy.sh
```

## 🔄 Manual Deployment

You can also trigger deployment manually:

1. Go to **Actions** tab in your GitHub repository
2. Select **Deploy to Production** workflow
3. Click **Run workflow** button

## 🔍 Monitoring Deployments

- **View logs**: Check the Actions tab for deployment logs
- **Health checks**: The workflow automatically verifies deployment
- **Server logs**: SSH to your VPS and check `docker-compose logs -f`

## 🛠️ Troubleshooting

### Common Issues

**SSH Connection Failed:**
- Verify SSH key is correctly added to GitHub secrets
- Ensure public key is in `~/.ssh/authorized_keys` on VPS
- Check VPS firewall allows SSH (port 22)

**Deployment Script Failed:**
- SSH to VPS and run deployment manually to debug
- Check Docker and Docker Compose are installed
- Verify `.env` file is properly configured

**Health Check Failed:**
- Check application logs: `docker-compose logs backend`
- Verify Caddy configuration and domain setup
- Ensure all required environment variables are set

### Debug Commands

```bash
# SSH to your VPS
ssh user@your-vps-ip

# Check deployment manually
cd /opt/gobackend/deployment/production
./deploy.sh

# Check container status
docker-compose ps

# View logs
docker-compose logs -f
```

## 🔒 Security Notes

- **Never commit SSH keys** to your repository
- **Use strong SSH keys** (RSA 4096-bit or ED25519)
- **Regularly rotate SSH keys** for security
- **Limit SSH access** to specific IPs if possible
- **Use SSH key passphrases** for additional security

## 📝 Workflow Customization

To modify the deployment workflow:

1. Edit `.github/workflows/deploy.yml`
2. Adjust deployment paths, commands, or conditions
3. Add additional steps like running tests before deployment
4. Configure notifications (Slack, Discord, email, etc.)