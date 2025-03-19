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
                            bandit -r . -f json -o bandit-report.json -ll || exit 0
                            bandit -r . -f html -o bandit-report.html -ll || exit 0
                        '''
                        
                        def banditReport = readJSON file: 'bandit-report.json'
                        def metrics = banditReport.metrics
                        
                        // Count high severity issues across all files
                        def highSeverityCount = 0
                        def mediumSeverityCount = 0
                        metrics.each { file, fileMetrics ->
                            if (fileMetrics['SEVERITY.HIGH']) {
                                highSeverityCount += fileMetrics['SEVERITY.HIGH']
                            }
                            if (fileMetrics['SEVERITY.MEDIUM']) {
                                mediumSeverityCount += fileMetrics['SEVERITY.MEDIUM']
                            }
                        }
                        
                        // Create detailed report
                        def reportSummary = "Security Issues Found:\\n"
                        metrics.each { file, fileMetrics ->
                            if (fileMetrics['SEVERITY.HIGH'] > 0 || fileMetrics['SEVERITY.MEDIUM'] > 0) {
                                reportSummary += "- ${file}:\\n"
                                reportSummary += "  High: ${fileMetrics['SEVERITY.HIGH'] ?: 0}, Medium: ${fileMetrics['SEVERITY.MEDIUM'] ?: 0}\\n"
                            }
                        }
                        
                        slackSend(
                            channel: env.SLACK_CHANNEL,
                            color: highSeverityCount > 0 ? 'danger' : (mediumSeverityCount > 0 ? 'warning' : 'good'),
                            message: """
                            ${highSeverityCount > 0 ? '🚨' : mediumSeverityCount > 0 ? '⚠️' : '✅'} *SAST Scan Results*
                            - High Severity Issues: ${highSeverityCount}
                            - Medium Severity Issues: ${mediumSeverityCount}
                            ${reportSummary}
                            - Full Report: ${env.BUILD_URL}artifact/bandit-report.html
                            """
                        )
                        
                        if (highSeverityCount > 0) {
                            error('High severity security issues found')
                        }
                    } catch (Exception e) {
                        slackSend(
                            channel: env.SLACK_CHANNEL,
                            color: 'danger',
                            message: "❌ *SAST Scan Failed*\nError: ${e.getMessage()}"
                        )
                        error("SAST scan failed: ${e.getMessage()}")
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
                            pyraider check -f requirements.txt > pyraider-report.txt
                        '''
                        
                        def reportContent = readFile('pyraider-report.txt')
                        def hasCritical = reportContent.toLowerCase().contains('critical')
                        def hasHigh = reportContent.toLowerCase().contains('high')
                        
                        slackSend(
                            channel: env.SLACK_CHANNEL,
                            color: (hasCritical || hasHigh) ? 'danger' : 'warning',
                            message: """
                            ${(hasCritical || hasHigh) ? '🚨' : '⚠️'} *SCA Scan Results*
                            - Found ${hasCritical ? 'CRITICAL' : hasHigh ? 'HIGH' : 'MEDIUM/LOW'} severity vulnerabilities
                            - Report: ${env.BUILD_URL}artifact/pyraider-report.txt
                            """
                        )
                        
                        if (hasCritical || hasHigh) {
                            error('Critical/High severity vulnerabilities found in dependencies')
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
                        
                        writeFile file: 'security-report.md', text: """
                        # Security Analysis Report
                        
                        ## Overview
                        - Job: ${env.JOB_NAME}
                        - Build: ${env.BUILD_NUMBER}
                        - Date: ${new Date().format('yyyy-MM-dd HH:mm:ss')}
                        
                        ## Security Scan Results
                        - SAST Report: ${env.BUILD_URL}artifact/bandit-report.html
                        - SCA Report: ${env.BUILD_URL}artifact/pyraider-report.txt
                        
                        ## Remediation Guidelines
                        1. Review and fix all high severity issues immediately
                        2. Update dependencies with known vulnerabilities
                        3. Implement input validation for all user inputs
                        4. Use parameterized queries for database operations
                        5. Follow secure coding practices
                        
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
