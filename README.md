# Gemini Code Review & Security Analysis

This repository demonstrates how to use Gemini for automated code review and security analysis within a GitHub Actions workflow. The setup utilizes the `google-github-actions/run-gemini-cli` action to perform two distinct tasks on pull requests: a general code review using custom skills and a security analysis using a pre-built extension.

## How It Works

The workflow is defined in `.github/workflows/gemini-review.yml` and is triggered automatically whenever a pull request is opened, updated, or reopened. It consists of a single job that runs two main steps:

1.  **Gemini Pull Request Review**: This step performs a general code review. It uses a custom "skill" located in the `ai-skills/` directory. The prompt `/gemini-review` is used to invoke this skill, which guides the AI to review the code changes in the pull request.

2.  **Gemini Security Analysis**: This step focuses specifically on identifying potential security vulnerabilities. It leverages the `gemini-cli-extensions/security` extension and is invoked with the prompt `/security:analyze-github-pr`.

The results of both analyses are posted as comments on the pull request.

## Configuration

To use this workflow in your own repository, you need to configure several GitHub secrets and variables.

### Repository Secrets

These should be configured under your repository's `Settings > Secrets and variables > Actions > Secrets`.

*   `GEMINI_API_KEY` or `GOOGLE_API_KEY`: Your API key for the Gemini API.
*   `GITHUB_TOKEN`: This is automatically provided by GitHub, but you need to ensure the workflow has the correct permissions (`pull-requests: write`, `issues: write`).

### Repository Variables(optional)

These should be configured under your repository's `Settings > Secrets and variables > Actions > Variables`.

*   `GOOGLE_CLOUD_PROJECT`: Your Google Cloud Project ID.
*   `GOOGLE_CLOUD_LOCATION`: The Google Cloud region for your project (e.g., `us-central1`).
*   `SERVICE_ACCOUNT_EMAIL`: The email address of the Google Cloud Service Account used for authentication.
*   `GCP_WIF_PROVIDER`: The full identifier of your Workload Identity Federation provider.
*   `GEMINI_MODEL`: The Gemini model to use (e.g., `gemini-1.5-pro-latest`).

## Customization

### General Code Review

The behavior of the general code review can be customized by modifying the skill definition in the `ai-skills/gemini-review` file. This file contains the core prompt and instructions that the Gemini model follows during the review.

### Security Analysis

The security analysis relies on a pre-built extension. While the prompt is fixed in the workflow file, you could fork the extension or create your own to customize the security audit logic.
