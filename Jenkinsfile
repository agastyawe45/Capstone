pipeline {
    agent any

    environment {
        SLACK_CHANNEL = '#jenkins-notifications'
        SLACK_TOKEN = credentials('slack-token')
        PYTHON_PATH = 'C:\\Python312\\python.exe'  // Adjust this path to your Python installation
    }

    stages {
        stage('Checkout') {
            steps {
                // Clean workspace before checkout
                cleanWs()
                checkout scm
            }
            post {
                success {
                    slackSend(
                        channel: env.SLACK_CHANNEL,
                        color: 'good',
                        message: """
                        ✅ *Source Code Checkout Complete*
                        - Repository: ${env.GIT_URL ?: 'N/A'}
                        - Branch: ${env.GIT_BRANCH ?: 'N/A'}
                        - Commit: ${env.GIT_COMMIT ?: 'N/A'}
                        """
                    )
                }
            }
        }

        stage('Setup Python Environment') {
            steps {
                bat '''
                    python -m venv venv
                    call venv\\Scripts\\activate.bat
                    python -m pip install --upgrade pip
                    pip install -r requirements.txt
                    pip install bandit safety pytest
                '''
            }
        }

        stage('Run Unit Tests') {
            steps {
                bat '''
                    call venv\\Scripts\\activate.bat
                    python -m pytest tests/ --junitxml=test-results.xml
                '''
            }
            post {
                always {
                    junit 'test-results.xml'
                }
            }
        }

        stage('SAST - Bandit Security Scan') {
            steps {
                script {
                    try {
                        bat '''
                            call venv\\Scripts\\activate.bat
                            bandit -r . -f json -o bandit-report.json
                            bandit -r . -f html -o bandit-report.html
                        '''
                        
                        def banditReport = readJSON file: 'bandit-report.json'
                        def highSeverityCount = banditReport.metrics.SEVERITY.HIGH ?: 0
                        def mediumSeverityCount = banditReport.metrics.SEVERITY.MEDIUM ?: 0
                        
                        if (highSeverityCount > 0 || mediumSeverityCount > 0) {
                            slackSend(
                                channel: env.SLACK_CHANNEL,
                                color: 'danger',
                                message: """
                                🚨 *Security Issues Detected*
                                - High Severity: ${highSeverityCount}
                                - Medium Severity: ${mediumSeverityCount}
                                - Details: ${env.BUILD_URL}artifact/bandit-report.html
                                """
                            )
                            currentBuild.result = 'UNSTABLE'
                        }
                    } catch (Exception e) {
                        error "SAST scanning failed: ${e.message}"
                    }
                }
            }
        }

        stage('SCA - Dependencies Security Check') {
            steps {
                script {
                    try {
                        bat '''
                            call venv\\Scripts\\activate.bat
                            safety check --json > safety-report.json
                            safety check --output text > safety-report.txt
                        '''
                        
                        def safetyReport = readJSON file: 'safety-report.json'
                        if (safetyReport.size() > 0) {
                            slackSend(
                                channel: env.SLACK_CHANNEL,
                                color: 'warning',
                                message: """
                                ⚠️ *Dependency Vulnerabilities Found*
                                - Number of Issues: ${safetyReport.size()}
                                - Report: ${env.BUILD_URL}artifact/safety-report.txt
                                """
                            )
                            currentBuild.result = 'UNSTABLE'
                        }
                    } catch (Exception e) {
                        error "SCA scanning failed: ${e.message}"
                    }
                }
            }
        }

        stage('Security Report Analysis') {
            steps {
                script {
                    try {
                        def banditReport = readJSON file: 'bandit-report.json'
                        def summary = """
                            🔒 *Security Scan Summary*
                            
                            SAST Results (Bandit):
                            - High Severity: ${banditReport.metrics.SEVERITY.HIGH ?: 0}
                            - Medium Severity: ${banditReport.metrics.SEVERITY.MEDIUM ?: 0}
                            - Low Severity: ${banditReport.metrics.SEVERITY.LOW ?: 0}
                            
                            Detailed findings available in build artifacts:
                            - Bandit Report: ${env.BUILD_URL}artifact/bandit-report.html
                            - Safety Report: ${env.BUILD_URL}artifact/safety-report.txt
                        """
                        
                        writeFile file: 'security-summary.txt', text: summary
                        archiveArtifacts artifacts: '''
                            *-report.json,
                            *-report.html,
                            *-report.txt,
                            security-summary.txt
                        ''', fingerprint: true
                        
                        echo summary
                    } catch (Exception e) {
                        error "Report analysis failed: ${e.message}"
                    }
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
                ✅ *Pipeline Completed Successfully*
                - Job: ${env.JOB_NAME} #${env.BUILD_NUMBER}
                - Duration: ${currentBuild.durationString}
                - Results: ${env.BUILD_URL}
                """
            )
        }
        unstable {
            slackSend(
                channel: env.SLACK_CHANNEL,
                color: 'warning',
                message: """
                ⚠️ *Pipeline Unstable - Security Issues Found*
                - Job: ${env.JOB_NAME} #${env.BUILD_NUMBER}
                - Duration: ${currentBuild.durationString}
                - Security Reports: ${env.BUILD_URL}artifact/
                Please review the security findings and take necessary actions.
                """
            )
        }
        failure {
            slackSend(
                channel: env.SLACK_CHANNEL,
                color: 'danger',
                message: """
                ❌ *Pipeline Failed*
                - Job: ${env.JOB_NAME} #${env.BUILD_NUMBER}
                - Duration: ${currentBuild.durationString}
                - Error Details: ${env.BUILD_URL}console
                """
            )
        }
        always {
            cleanWs()
        }
    }
} 
