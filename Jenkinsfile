pipeline {
    agent any

    environment {
        SLACK_CHANNEL = '#jenkins-notifications'
        SLACK_TOKEN = credentials('slack-token')
    }

    stages {
        stage('Checkout') {
            steps {
                checkout scm
            }
            post {
                success {
                    slackSend(
                        channel: env.SLACK_CHANNEL,
                        color: 'good',
                        message: "✅ Code checkout successful: ${env.JOB_NAME} #${env.BUILD_NUMBER}"
                    )
                }
                failure {
                    slackSend(
                        channel: env.SLACK_CHANNEL,
                        color: 'danger',
                        message: "❌ Code checkout failed: ${env.JOB_NAME} #${env.BUILD_NUMBER}"
                    )
                }
            }
        }

        stage('Install Dependencies') {
            steps {
                bat '''
                    python -m pip install --upgrade pip
                    pip install -r requirements.txt
                    pip install bandit safety pytest
                '''
            }
        }

        stage('Run Tests') {
            steps {
                bat 'python -m pytest tests/'
            }
        }

        stage('SAST - Bandit Scan') {
            steps {
                script {
                    try {
                        bat 'bandit -r . -f json -o bandit-report.json'
                        def banditReport = readJSON file: 'bandit-report.json'
                        
                        if (banditReport.results.size() > 0) {
                            slackSend(
                                channel: env.SLACK_CHANNEL,
                                color: 'warning',
                                message: """
                                ⚠️ *Security Issues Found*
                                - Job: ${env.JOB_NAME} #${env.BUILD_NUMBER}
                                - Issues: ${banditReport.results.size()}
                                - Details: ${env.BUILD_URL}artifact/bandit-report.json
                                """
                            )
                        }
                    } catch (Exception e) {
                        slackSend(
                            channel: env.SLACK_CHANNEL,
                            color: 'danger',
                            message: "❌ SAST scan failed: ${e.message}"
                        )
                        currentBuild.result = 'UNSTABLE'
                    }
                }
            }
        }

        stage('SCA - Safety Check') {
            steps {
                script {
                    try {
                        bat 'safety check --json > safety-report.json || exit 0'
                        def safetyReport = readJSON file: 'safety-report.json'
                        
                        if (safetyReport.size() > 0) {
                            echo "Safety found dependency issues"
                            currentBuild.result = 'UNSTABLE'
                        }
                    } catch (Exception e) {
                        echo "Error in Safety check: ${e.message}"
                        currentBuild.result = 'UNSTABLE'
                    }
                }
            }
        }

        stage('Security Report Analysis') {
            steps {
                script {
                    try {
                        def banditReport = readJSON file: 'bandit-report.json'
                        def highCount = 0
                        def mediumCount = 0
                        def lowCount = 0
                        
                        banditReport.results.each { issue ->
                            switch(issue.issue_severity) {
                                case 'HIGH': highCount++; break
                                case 'MEDIUM': mediumCount++; break
                                case 'LOW': lowCount++; break
                            }
                        }
                        
                        def summary = """
                            Security Scan Results:
                            Total Issues: ${banditReport.results.size()}
                            High Severity: ${highCount}
                            Medium Severity: ${mediumCount}
                            Low Severity: ${lowCount}
                            
                            Details of High Severity Issues:
                            ${banditReport.results.findAll { it.issue_severity == 'HIGH' }.collect { 
                                "- ${it.issue_text} in ${it.filename}:${it.line_number}"
                            }.join('\n')}
                        """
                        
                        echo summary
                        writeFile file: 'security-summary.txt', text: summary
                        archiveArtifacts artifacts: '*-report.*,security-summary.txt', fingerprint: true
                        
                        if (highCount > 0) {
                            currentBuild.result = 'UNSTABLE'
                        }
                    } catch (Exception e) {
                        echo "Error analyzing security reports: ${e.message}"
                        currentBuild.result = 'UNSTABLE'
                    }
                }
            }
            post {
                always {
                    slackSend(
                        channel: env.SLACK_CHANNEL,
                        color: currentBuild.result == 'SUCCESS' ? 'good' : 'warning',
                        message: """
                        *Security Scan Results*
                        Job: ${env.JOB_NAME} #${env.BUILD_NUMBER}
                        Status: ${currentBuild.result ?: 'SUCCESS'}
                        Details: ${env.BUILD_URL}
                        """
                    )
                }
            }
        }
    }

    post {
        success {
            slackSend(
                channel: env.SLACK_CHANNEL,
                color: 'good',
                message: """
                ✅ *Pipeline Successful*
                Job: ${env.JOB_NAME} #${env.BUILD_NUMBER}
                Duration: ${currentBuild.durationString}
                URL: ${env.BUILD_URL}
                """
            )
        }
        unstable {
            slackSend(
                channel: env.SLACK_CHANNEL,
                color: 'warning',
                message: """
                ⚠️ *Pipeline Unstable*
                Job: ${env.JOB_NAME} #${env.BUILD_NUMBER}
                Duration: ${currentBuild.durationString}
                URL: ${env.BUILD_URL}
                - Security vulnerabilities were found
                - Check the security reports in the build artifacts
                """
            )
        }
        failure {
            slackSend(
                channel: env.SLACK_CHANNEL,
                color: 'danger',
                message: """
                ❌ *Pipeline Failed*
                Job: ${env.JOB_NAME} #${env.BUILD_NUMBER}
                Duration: ${currentBuild.durationString}
                URL: ${env.BUILD_URL}
                """
            )
        }
        always {
            cleanWs()
        }
    }
} 
