pipeline {
    agent any

    environment {
        DOCKER_IMAGE = 'capstone-devsecops'
        DOCKER_TAG = "${BUILD_NUMBER}"
        DOCKER_PATH = '"C:\\Program Files\\Docker\\Docker\\resources\\bin\\docker.exe"'
        APP_PORT = '5000'
        DOCKER_DESKTOP = true  // Set to true if using Docker Desktop
        DOCKER_OPTIONAL = true  // Set to true to make Docker stages optional
    }

    stages {
        stage('Checkout') {
            steps {
                checkout scm
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
                        bat 'bandit -r . -f html -o bandit-report.html || echo "HTML report generation failed but continuing"'
                        archiveArtifacts artifacts: 'bandit-report.*', fingerprint: true
                    } catch (err) {
                        echo "Bandit found security issues"
                        currentBuild.result = 'UNSTABLE'
                    }
                }
            }
        }

        stage('SCA - Safety Check') {
            steps {
                script {
                    try {
                        bat 'safety check --json > safety-report.json'
                        bat 'safety check --output text > safety-report.txt || echo "Text report generation failed but continuing"'
                        archiveArtifacts artifacts: 'safety-report.*', fingerprint: true
                    } catch (err) {
                        echo "Safety found dependency issues"
                        currentBuild.result = 'UNSTABLE'
                    }
                }
            }
        }

        stage('Check Docker Installation') {
            steps {
                script {
                    def dockerInstalled = false
                    try {
                        def dockerCheck = bat(script: 'where docker', returnStatus: true)
                        if (dockerCheck == 0) {
                            echo "Docker found on system"
                            dockerInstalled = true
                        } else {
                            echo "Docker not found on system"
                            if (env.DOCKER_OPTIONAL.toBoolean()) {
                                echo "Skipping Docker-dependent stages as Docker is optional"
                                currentBuild.result = 'UNSTABLE'
                            }
                        }
                    } catch (Exception e) {
                        echo "Docker check failed: ${e.message}"
                        if (env.DOCKER_OPTIONAL.toBoolean()) {
                            echo "Skipping Docker-dependent stages"
                            currentBuild.result = 'UNSTABLE'
                        }
                    }
                    env.DOCKER_INSTALLED = dockerInstalled.toString()
                }
            }
        }

        stage('Build Docker Image') {
            when {
                expression { return env.DOCKER_INSTALLED == 'true' }
            }
            steps {
                script {
                    try {
                        bat 'docker build -t capstone-devsecops:%BUILD_NUMBER% -f docker/Dockerfile .'
                    } catch (err) {
                        echo "Docker build failed: ${err}"
                        currentBuild.result = 'UNSTABLE'
                    }
                }
            }
        }

        stage('Run Container') {
            steps {
                script {
                    try {
                        // Stop and remove any existing container with same name
                        bat """
                            for /f "tokens=*" %%i in ('%DOCKER_PATH% ps -q --filter name=${DOCKER_IMAGE}_${BUILD_NUMBER}') do (
                                %DOCKER_PATH% stop %%i 2>nul
                                %DOCKER_PATH% rm %%i 2>nul
                            )
                        """
                        
                        // Run new container
                        bat "%DOCKER_PATH% run -d --name ${DOCKER_IMAGE}_${BUILD_NUMBER} -p ${APP_PORT}:5000 ${DOCKER_IMAGE}:${DOCKER_TAG}"
                        
                        // Wait for application to start
                        bat "timeout /t 10 /nobreak"
                        
                        // Test if application is running
                        bat "curl http://localhost:${APP_PORT} || echo Application may not be running properly"
                    } catch (err) {
                        echo "Warning: Container execution had issues: ${err}"
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
                        
                        if (banditReport.results) {
                            echo "Found ${banditReport.results.size()} security issues in total"
                            
                            banditReport.results.each { issue ->
                                if (issue.issue_severity == 'HIGH') {
                                    highCount++
                                } else if (issue.issue_severity == 'MEDIUM') {
                                    mediumCount++
                                }
                            }
                            
                            echo "Security issues: ${highCount} HIGH, ${mediumCount} MEDIUM"
                            
                            if (highCount > 0) {
                                echo "High severity issues found in code!"
                                currentBuild.result = 'UNSTABLE'
                            }

                            // Generate summary report
                            def summaryReport = """Security Scan Summary:
                            Total Issues: ${banditReport.results.size()}
                            High Severity: ${highCount}
                            Medium Severity: ${mediumCount}
                            
                            Details:
                            ${banditReport.results.collect { issue ->
                                "- ${issue.issue_severity}: ${issue.issue_text} (${issue.filename}:${issue.line_number})"
                            }.join('\n')}
                            """
                            
                            writeFile file: 'security-summary.txt', text: summaryReport
                            archiveArtifacts artifacts: 'security-summary.txt', fingerprint: true
                        } else {
                            echo "No security issues found in Bandit scan"
                        }
                        
                        echo "Security scanning completed successfully"
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
                    // Cleanup containers with error handling
                    bat """
                        for /f "tokens=*" %%i in ('%DOCKER_PATH% ps -a -q --filter name=${DOCKER_IMAGE}_${BUILD_NUMBER}') do (
                            %DOCKER_PATH% stop %%i 2>nul
                            %DOCKER_PATH% rm %%i 2>nul
                        )
                    """
                } catch (Exception e) {
                    echo "Warning: Container cleanup had issues: ${e.message}"
                }
            }
            cleanWs()
        }
        success {
            echo 'Pipeline completed successfully!'
        }
        unstable {
            echo '''
            Pipeline completed with issues:
            1. Security vulnerabilities were found in the code
            2. Check the security reports in the build artifacts
            3. Docker stages were skipped (Docker not available)
            '''
        }
        failure {
            echo 'Pipeline failed! Check the logs for details.'
        }
    }
} 
