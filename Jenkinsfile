pipeline {
    agent any

    environment {
        SLACK_CHANNEL = '#jenkins-notifications'
        SLACK_TOKEN = credentials('slack-token')
    }

    options {
        timeout(time: 30, unit: 'MINUTES')
        buildDiscarder(logRotator(numToKeepStr: '10'))
    }

    stages {
        stage('Checkout') {
            steps {
                cleanWs()
                checkout scm
                slackSend(
                    channel: env.SLACK_CHANNEL,
                    color: 'good',
                    message: "🔄 Started Pipeline: ${env.JOB_NAME} #${env.BUILD_NUMBER}"
                )
            }
        }

        stage('Setup Python Environment') {
            steps {
                bat '''
                    python -m venv venv
                    call venv\\Scripts\\activate.bat
                    python -m pip install --upgrade pip
                    pip install -r requirements.txt
                '''
            }
        }

        stage('SAST - Bandit Security Scan') {
            steps {
                script {
                    try {
                        bat '''
                            call venv\\Scripts\\activate.bat
                            bandit -r . -f json -o bandit-report.json || exit 0
                            bandit -r . -f html -o bandit-report.html || exit 0
                        '''
                        
                        def banditReport = readJSON file: 'bandit-report.json'
                        def metrics = banditReport.metrics ?: [:]
                        def severity = metrics.SEVERITY ?: [:]
                        
                        def highSeverityCount = severity.HIGH ?: 0
                        def mediumSeverityCount = severity.MEDIUM ?: 0
                        
                        slackSend(
                            channel: env.SLACK_CHANNEL,
                            color: highSeverityCount > 0 ? 'danger' : 'good',
                            message: """
                            ${highSeverityCount > 0 ? '🚨' : '✅'} *SAST Scan Results*
                            - High Severity Issues: ${highSeverityCount}
                            - Medium Severity Issues: ${mediumSeverityCount}
                            - Report: ${env.BUILD_URL}artifact/bandit-report.html
                            """
                        )
                        
                        if (highSeverityCount > 0) {
                            unstable('High severity security issues found')
                        }
                    } catch (Exception e) {
                        slackSend(
                            channel: env.SLACK_CHANNEL,
                            color: 'danger',
                            message: "❌ *SAST Scan Failed*\nError: ${e.getMessage()}"
                        )
                        unstable("SAST scan failed: ${e.getMessage()}")
                    }
                }
            }
        }

        stage('SCA - Pyraider Security Check') {
            steps {
                script {
                    try {
                        bat '''
                            call venv\\Scripts\\activate.bat
                            pyraider check -f requirements.txt -e json pyraider-report.json
                        '''
                        
                        def pyraiderReport = readJSON file: 'pyraider-report.json'
                        def criticalVulnerabilities = pyraiderReport.findAll { it.severity == 'CRITICAL' }.size()
                        def highVulnerabilities = pyraiderReport.findAll { it.severity == 'HIGH' }.size()
                        
                        slackSend(
                            channel: env.SLACK_CHANNEL,
                            color: criticalVulnerabilities > 0 ? 'danger' : 'good',
                            message: """
                            ${criticalVulnerabilities > 0 ? '🚨' : '✅'} *SCA Results*
                            - Critical Vulnerabilities: ${criticalVulnerabilities}
                            - High Vulnerabilities: ${highVulnerabilities}
                            - Report: ${env.BUILD_URL}artifact/pyraider-report.json
                            """
                        )
                        
                        if (criticalVulnerabilities > 0) {
                            error('Critical vulnerabilities found in dependencies - Pipeline failed')
                        }
                    } catch (Exception e) {
                        slackSend(
                            channel: env.SLACK_CHANNEL,
                            color: 'danger',
                            message: "❌ *SCA Check Failed*\nError: ${e.getMessage()}"
                        )
                        error("SCA check failed: ${e.getMessage()}")
                    }
                }
            }
        }

        stage('Documentation') {
            steps {
                script {
                    try {
                        bat '''
                            call venv\\Scripts\\activate.bat
                            pdoc3 --html --output-dir docs app/
                        '''
                        
                        // Generate security report and remediation guide
                        writeFile file: 'security-report.md', text: """
                        # Security Analysis Report
                        
                        ## Overview
                        - Job: ${env.JOB_NAME}
                        - Build: ${env.BUILD_NUMBER}
                        - Date: ${new Date().format('yyyy-MM-dd HH:mm:ss')}
                        
                        ## Security Scan Results
                        - SAST Report: ${env.BUILD_URL}artifact/bandit-report.html
                        - SCA Report: ${env.BUILD_URL}artifact/pyraider-report.json
                        
                        ## Remediation Guidelines
                        1. Address all high severity issues immediately
                        2. Update vulnerable dependencies
                        3. Follow secure coding practices
                        4. Implement input validation
                        5. Use parameterized queries
                        
                        ## Documentation
                        - API Documentation: ${env.BUILD_URL}artifact/docs/index.html
                        """
                        
                        archiveArtifacts artifacts: '''
                            docs/**/*,
                            *-report.*,
                            security-report.md
                        ''', fingerprint: true
                        
                        slackSend(
                            channel: env.SLACK_CHANNEL,
                            color: 'good',
                            message: """
                            📚 *Documentation Generated*
                            - Security Report: ${env.BUILD_URL}artifact/security-report.md
                            - API Docs: ${env.BUILD_URL}artifact/docs/index.html
                            """
                        )
                    } catch (Exception e) {
                        slackSend(
                            channel: env.SLACK_CHANNEL,
                            color: 'warning',
                            message: "⚠️ *Documentation Generation Failed*\nError: ${e.getMessage()}"
                        )
                        unstable("Documentation failed but continuing pipeline")
                    }
                }
            }
        }
    }

    post {
        always {
            archiveArtifacts artifacts: '''
                *-report.*,
                docs/**/*,
                security-report.md
            ''', allowEmptyArchive: true
            cleanWs()
        }
        success {
            slackSend(
                channel: env.SLACK_CHANNEL,
                color: 'good',
                message: """
                ✅ *Pipeline Completed Successfully*
                - Job: ${env.JOB_NAME} #${env.BUILD_NUMBER}
                - Reports: ${env.BUILD_URL}artifact/
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
                - Check the build logs: ${env.BUILD_URL}console
                """
            )
        }
    }
} 
