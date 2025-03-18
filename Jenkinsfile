pipeline {
    agent any

    environment {
        DOCKER_IMAGE = 'capstone-devsecops'
        DOCKER_TAG = "${BUILD_NUMBER}"
        DOCKER_PATH = '"C:\\Program Files\\Docker\\Docker\\resources\\bin\\docker.exe"'
        APP_PORT = '5000'
        DOCKER_DESKTOP = true  // Set to true if using Docker Desktop
        DOCKER_OPTIONAL = true  // Set to true to make Docker stages optional
        SLACK_CHANNEL = '#jenkins-notifications'
        SLACK_TOKEN = credentials('slack-token') // Configure this in Jenkins credentials
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
                                message: "⚠️ Security Issues Found - ${banditReport.results.size()} issues detected"
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
                    bat 'safety check --json > safety-report.json || exit 0'
                    def safetyReport = readJSON file: 'safety-report.json'
                    if (safetyReport.size() > 0) {
                        echo "Safety found dependency issues"
                        currentBuild.result = 'UNSTABLE'
                    }
                }
            }
        }

        stage('Check Docker Installation') {
            steps {
                script {
                    try {
                        def dockerCheck = bat(script: 'where docker', returnStatus: true)
                        if (dockerCheck == 0) {
                            echo "Docker found on system"
                            env.DOCKER_INSTALLED = 'true'
                        } else {
                            echo "Docker not found on system"
                            env.DOCKER_INSTALLED = 'false'
                            if (env.DOCKER_OPTIONAL.toBoolean()) {
                                echo "Skipping Docker-dependent stages as Docker is optional"
                                currentBuild.result = 'UNSTABLE'
                            }
                        }
                    } catch (Exception e) {
                        echo "Docker check failed: ${e.message}"
                        env.DOCKER_INSTALLED = 'false'
                        currentBuild.result = 'UNSTABLE'
                    }
                }
            }
        }

        stage('Build Docker Image') {
            steps {
                script {
                    try {
                        // Clean up existing containers and images
                        bat '''
                            docker ps -q --filter "name=%DOCKER_IMAGE%" | findstr . && docker stop $(docker ps -q --filter "name=%DOCKER_IMAGE%") || echo "No containers to stop"
                            docker ps -aq --filter "name=%DOCKER_IMAGE%" | findstr . && docker rm $(docker ps -aq --filter "name=%DOCKER_IMAGE%") || echo "No containers to remove"
                            docker images -q %DOCKER_IMAGE% | findstr . && docker rmi $(docker images -q %DOCKER_IMAGE%) || echo "No images to remove"
                        '''
                        
                        // Build new image
                        bat "docker build -t ${DOCKER_IMAGE}:${DOCKER_TAG} ."
                        
                        slackSend(
                            channel: env.SLACK_CHANNEL,
                            color: 'good',
                            message: "✅ Docker image built successfully: ${DOCKER_IMAGE}:${DOCKER_TAG}"
                        )
                    } catch (Exception e) {
                        slackSend(
                            channel: env.SLACK_CHANNEL,
                            color: 'danger',
                            message: "❌ Docker build failed: ${e.message}"
                        )
                        error "Docker build failed: ${e.message}"
                    }
                }
            }
        }

        stage('Run Docker Container') {
            steps {
                script {
                    try {
                        // Run container
                        bat "docker run -d --name ${DOCKER_IMAGE}_${BUILD_NUMBER} -p ${APP_PORT}:5000 ${DOCKER_IMAGE}:${DOCKER_TAG}"
                        
                        // Wait for container to start
                        bat "timeout /t 10 /nobreak"
                        
                        // Verify container is running
                        bat "docker ps --filter name=${DOCKER_IMAGE}_${BUILD_NUMBER}"
                        
                        slackSend(
                            channel: env.SLACK_CHANNEL,
                            color: 'good',
                            message: "✅ Container started successfully: ${DOCKER_IMAGE}_${BUILD_NUMBER}"
                        )
                    } catch (Exception e) {
                        slackSend(
                            channel: env.SLACK_CHANNEL,
                            color: 'danger',
                            message: "❌ Container startup failed: ${e.message}"
                        )
                        error "Container startup failed: ${e.message}"
                    }
                }
            }
        }

        stage('DAST - OWASP ZAP Scan') {
            steps {
                script {
                    try {
                        // Create directory for ZAP report
                        bat 'mkdir zap-report || echo "Directory exists"'
                        
                        // Run ZAP scan
                        bat """
                            docker run --rm -v "%CD%/zap-report:/zap/wrk/:rw" ^
                            --network="host" ^
                            -t owasp/zap2docker-stable zap-baseline.py ^
                            -t http://localhost:${APP_PORT} ^
                            -r zap-report.html ^
                            -I
                        """
                        
                        // Archive ZAP report
                        archiveArtifacts artifacts: 'zap-report/*', fingerprint: true
                        
                        slackSend(
                            channel: env.SLACK_CHANNEL,
                            color: 'good',
                            message: "✅ DAST scan completed successfully"
                        )
                    } catch (Exception e) {
                        slackSend(
                            channel: env.SLACK_CHANNEL,
                            color: 'danger',
                            message: "❌ DAST scan failed: ${e.message}"
                        )
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
                        def summary = generateSecuritySummary(banditReport)
                        
                        echo summary
                        writeFile file: 'security-summary.txt', text: summary
                        archiveArtifacts artifacts: '*-report.*,security-summary.txt', fingerprint: true
                        
                        if (hasHighSeverityIssues(banditReport)) {
                            currentBuild.result = 'UNSTABLE'
                        }
                    } catch (Exception e) {
                        echo "Error analyzing security reports: ${e.message}"
                        currentBuild.result = 'UNSTABLE'
                    }
                }
            }
        }
    }

    post {
        always {
            script {
                try {
                    // Cleanup Docker resources
                    bat """
                        docker stop ${DOCKER_IMAGE}_${BUILD_NUMBER} || echo "Container not running"
                        docker rm ${DOCKER_IMAGE}_${BUILD_NUMBER} || echo "Container not found"
                        docker rmi ${DOCKER_IMAGE}:${DOCKER_TAG} || echo "Image not found"
                    """
                } catch (Exception e) {
                    echo "Warning: Cleanup had issues: ${e.message}"
                }
                cleanWs()
            }
            
            slackSend(
                channel: env.SLACK_CHANNEL,
                color: currentBuild.result == 'SUCCESS' ? 'good' : 'danger',
                message: """
                *Pipeline ${currentBuild.result}*
                Job: ${env.JOB_NAME} #${env.BUILD_NUMBER}
                Duration: ${currentBuild.durationString}
                URL: ${env.BUILD_URL}
                """
            )
        }
    }
}

// Helper function to generate security summary
def generateSecuritySummary(banditReport) {
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
    
    return """
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
}

// Helper function to check for high severity issues
def hasHighSeverityIssues(banditReport) {
    return banditReport.results.any { it.issue_severity == 'HIGH' }
} 
