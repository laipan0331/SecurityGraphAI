# 🚀 Git Repository Setup Guide

For SecurityGraph AI Project Team Members

---

## 📋 First-Time Setup (One-Time Only)

### 1. Initialize Git Repository

```bash
# Navigate to project directory
cd c:\Users\panpa\Desktop\SecurityGraphAI

# Initialize Git repository
git init

# Configure your information
git config user.name "Your Name"
git config user.email "your.email@example.com"
```

### 2. Create GitHub Repository

1. Visit [GitHub](https://github.com)
2. Click upper-right "+" → "New repository"
3. Repository name: `SecurityGraphAI`
4. Description: `Cybersecurity Knowledge Graph with GraphRAG - DAMG 7374 Project`
5. **Choose Public or Private** (based on course requirements)
6. **Do NOT check** "Initialize with README" (we already have one)
7. Click "Create repository"

### 3. Connect to GitHub

```bash
# Add remote repository (replace YOUR_USERNAME with your GitHub username)
git remote add origin https://github.com/YOUR_USERNAME/SecurityGraphAI.git

# Add all files
git add .

# First commit
git commit -m "Initial commit: Data Engineering work (CVE pipeline complete)"

# Push to GitHub
git branch -M main
git push -u origin main
```

---

## 📤 Daily Workflow

### Team Members Clone Repository

```bash
# Clone repository locally
git clone https://github.com/YOUR_USERNAME/SecurityGraphAI.git
cd SecurityGraphAI

# Install dependencies
python -m venv venv
venv\Scripts\activate  # Windows
pip install -r requirements.txt

# Copy environment variable template
cp .env.example .env
# Then edit .env file and add your API keys
```

### Create New Feature Branch

```bash
# Update main branch
git checkout main
git pull origin main

# Create new feature branch
git checkout -b feature/your-feature-name

# Examples:
# git checkout -b feature/neo4j-setup          (Graph Engineer)
# git checkout -b feature/streamlit-dashboard  (AI Engineer)
# git checkout -b feature/owasp-data           (Data Engineer)
```

### Commit Your Changes

```bash
# View modified files
git status

# Add files to staging area
git add .                    # Add all files
# or
git add path/to/file.py      # Add specific file

# Commit changes
git commit -m "Add: Brief description of what you did"

# Examples:
# git commit -m "Add: Neo4j connection utility"
# git commit -m "Add: OWASP vulnerability data CSV"
# git commit -m "Fix: CVSS score parsing bug"
```

### Push to GitHub

```bash
# Push to remote branch
git push origin feature/your-feature-name
```

### Create Pull Request

1. Visit GitHub repository page
2. Click "Pull requests" → "New pull request"
3. Base: `main` ← Compare: `feature/your-feature-name`
4. Add title and description
5. Request team member review
6. Merge after approval

### Update Local Code

```bash
# Switch to main branch
git checkout main

# Pull latest code
git pull origin main

# Switch back to your working branch
git checkout feature/your-feature-name

# Merge main branch updates into your branch
git merge main
```

---

## 🎯 Branch Naming Convention

```bash
feature/feature-name     # New feature
fix/bug-name            # Bug fix
docs/doc-name           # Documentation update
refactor/refactor-name  # Code refactoring

# Examples:
feature/graph-schema
feature/dashboard-ui
fix/cvss-score-parsing
docs/update-readme
```

---

## 📝 Commit Message Convention

```bash
Add: New feature or file
Fix: Bug fix
Update: Update existing feature
Refactor: Refactor code
Docs: Documentation update
Style: Code formatting
Test: Add tests

# Examples:
git commit -m "Add: Neo4j connection module"
git commit -m "Fix: Handle missing CVSS scores in preprocessing"
git commit -m "Update: Improve OWASP data collection script"
git commit -m "Docs: Add GraphRAG implementation guide"
```

---

## ⚠️ Important Notes

### 1. Never Commit Sensitive Information

```bash
# These are already in .gitignore:
.env                    # API keys
*.env                   # All environment variable files
__pycache__/            # Python cache
venv/                   # Virtual environment
```

### 2. Check .env File

```bash
# Confirm .env is in .gitignore
cat .gitignore | grep .env

# If accidentally added .env, remove immediately:
git rm --cached .env
git commit -m "Remove sensitive .env file"
```

### 3. Large File Handling

```bash
# If data files are large (>100MB), notify team
# Consider:
# - Add to .gitignore
# - Share via Google Drive/Dropbox
# - Or use Git LFS
```

### 4. Merge Conflict Resolution

```bash
# If merge conflicts occur:
git pull origin main

# Git will tell you which files have conflicts
# Open conflicted files and look for:
# <<<<<<< HEAD
# Your code
# =======
# Others' code
# >>>>>>> main

# After manually resolving conflicts:
git add .
git commit -m "Fix: Resolve merge conflicts"
git push
```

---

## 👥 Team Collaboration Best Practices

### 1. Pull Updates Frequently

```bash
# Before starting work each day
git checkout main
git pull origin main
git checkout feature/your-branch
git merge main
```

### 2. Small Commits, Frequent Pushes

```bash
# Good practice: Commit after completing a small feature
git add file.py
git commit -m "Add: Function to parse CWE data"
git push

# Bad practice: Work for a week before committing
```

### 3. Use Meaningful Commit Messages

```bash
# ✅ Good commit messages
git commit -m "Add: Neo4j connection with error handling"
git commit -m "Fix: CVSS score extraction for v2 fallback"

# ❌ Bad commit messages
git commit -m "update"
git commit -m "fix bug"
git commit -m "changes"
```

### 4. Code Review

- Create Pull Request instead of pushing directly to main
- Merge only after at least one team member reviews
- Provide constructive feedback politely

---

## 🆘 Common Questions

### Q: How do I view my changes?

```bash
git status              # View modified files
git diff                # View detailed changes
git log                 # View commit history
```

### Q: How do I undo changes?

```bash
# Undo unstaged changes
git checkout -- file.py

# Undo staged but uncommitted changes
git reset HEAD file.py

# Undo last commit (keep changes)
git reset --soft HEAD~1

# Revert to previous commit (discard all changes - use with caution!)
git reset --hard HEAD~1
```

### Q: How do I delete a created branch?

```bash
# Delete local branch
git branch -d feature/old-branch

# Delete remote branch
git push origin --delete feature/old-branch
```

### Q: What if I accidentally commit sensitive information?

```bash
# 1. Remove from Git history immediately
git rm --cached .env
git commit -m "Remove sensitive file"
git push

# 2. If file is already pushed to GitHub
# Change all exposed keys/passwords immediately!
# Then use git filter-branch to clean history (advanced operation)

# 3. Best practice: Prevention
# Always check that .gitignore is properly configured
```

---

## 📊 View Project Status

### View All Branches

```bash
# Local branches
git branch

# All branches (including remote)
git branch -a

# View branch relationships
git log --oneline --graph --all
```

### View Team Members' Work

```bash
# View all remote branches
git branch -r

# Pull all updates
git fetch origin

# Switch to others' branch to view
git checkout feature/their-branch
```

---

## ✅ Weekly Checklist

### Data Engineer (Panpan)
- [ ] Commit all new CSV files
- [ ] Update DATA_ENGINEERING.md progress
- [ ] Push ETL script updates
- [ ] Create data documentation

### Graph Engineer
- [ ] Commit Neo4j connection code
- [ ] Commit ETL loading scripts
- [ ] Commit Cypher query templates
- [ ] Document graph schema design

### AI Engineer
- [ ] Commit Streamlit pages
- [ ] Commit GraphRAG components
- [ ] Commit UI improvements
- [ ] Document API usage

---

## 🔗 Useful Git Resources

- [Git Basics Tutorial](https://git-scm.com/book/en/v2)
- [GitHub Documentation](https://docs.github.com/en)
- [Git Cheat Sheet](https://training.github.com/downloads/github-git-cheat-sheet/)
- [Visualizing Git](https://learngitbranching.js.org/)

---

## 📞 Need Help?

If you encounter Git issues:

1. **Search error message first** - Stack Overflow usually has answers
2. **Ask team members** - Others have likely encountered similar issues
3. **Check GitHub documentation** - Official docs are detailed
4. **Last resort** - Google / ChatGPT

---

**Created:** February 16, 2026  
**For:** All SecurityGraph AI Team Members  
**Maintainer:** Panpan Lai (Initial Setup)
