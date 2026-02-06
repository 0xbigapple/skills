# Gemini 代码审查与安全分析

该代码仓库演示了如何在 GitHub Actions 工作流中使用 Gemini 进行自动化的代码审查和安全分析。此设置利用 `google-github-actions/run-gemini-cli` action，在拉取请求（Pull Request）上执行两个不同的任务：使用自定义技能（skill）进行通用代码审查，以及使用预构建的扩展（extension）进行安全分析。

## 工作原理

工作流在 `.github/workflows/gemini-review.yml` 文件中定义，每当有拉取请求被创建、更新或重新打开时，它都会自动触发。该工作流包含一个作业（job），该作业运行两个主要步骤：

1.  **Gemini 拉取请求审查**: 此步骤执行通用的代码审查。它使用位于 `ai-skills/` 目录下的自定义“技能”。通过提示 `/gemini-review` 来调用此技能，引导 AI 审查拉取请求中的代码变更。

2.  **Gemini 安全分析**: 此步骤专门用于识别潜在的安全漏洞。它利用了 `gemini-cli-extensions/security` 扩展，并通过提示 `/security:analyze-github-pr` 来调用。

两个分析的结果都会作为评论发布在拉取请求上。

## 配置

要在您自己的代码仓库中使用此工作流，您需要配置几个 GitHub secrets 和 variables。

### 代码仓库 Secrets

这些应在您的代码仓库的 `Settings > Secrets and variables > Actions > Secrets` 下进行配置。

*   `GEMINI_API_KEY` 或 `GOOGLE_API_KEY`: 您的 Gemini API 密钥。
*   `GITHUB_TOKEN`: 这个由 GitHub 自动提供，但您需要确保工作流具有正确的权限（`pull-requests: write`, `issues: write`）。

### 代码仓库 Variables(可选)

这些应在您的代码仓库的 `Settings > Secrets and variables > Actions > Variables` 下进行配置。

*   `GOOGLE_CLOUD_PROJECT`: 您的 Google Cloud 项目 ID。
*   `GOOGLE_CLOUD_LOCATION`: 您的项目的 Google Cloud 区域（例如 `us-central1`）。
*   `SERVICE_ACCOUNT_EMAIL`: 用于身份验证的 Google Cloud 服务帐号的电子邮件地址。
*   `GCP_WIF_PROVIDER`: 您的 Workload Identity Federation 提供者的完整标识符。
*   `GEMINI_MODEL`: 要使用的 Gemini 模型（例如 `gemini-2.5-pro`）。

## 自定义

### 通用代码审查

通用代码审查的行为可以通过修改 `ai-skills/pr-review-stability/SKILL.md` 文件中的技能定义来自定义。该文件包含了 Gemini 模型在审查期间遵循的核心提示和指令。

### 安全分析

安全分析依赖于一个预构建的扩展。虽然提示在工作流文件中是固定的，但您可以 fork 该扩展或创建自己的扩展来自定义安全审计逻辑。
