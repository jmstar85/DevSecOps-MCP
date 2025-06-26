#!/bin/bash

# GitHub 저장소 생성 후 실행할 스크립트

echo "🚀 Pushing DevSecOps MCP Server to GitHub..."

# 원격 저장소가 이미 추가되어 있는지 확인
if git remote get-url origin > /dev/null 2>&1; then
    echo "✅ Remote origin already configured"
else
    echo "📍 Adding remote origin..."
    git remote add origin https://github.com/jmstar85/DevSecOps.git
fi

# 현재 상태 확인
echo "📊 Current git status:"
git status --short

echo "📋 Commit history:"
git log --oneline -5

# GitHub에 푸시
echo "⬆️  Pushing to GitHub..."
git push -u origin main

if [ $? -eq 0 ]; then
    echo "🎉 Successfully pushed to GitHub!"
    echo "🔗 Repository URL: https://github.com/jmstar85/DevSecOps"
    echo "📖 View README: https://github.com/jmstar85/DevSecOps#readme"
else
    echo "❌ Push failed. Please check:"
    echo "   1. Repository exists on GitHub"
    echo "   2. You have push permissions"
    echo "   3. Network connectivity"
fi