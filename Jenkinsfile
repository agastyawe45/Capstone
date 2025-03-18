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
                        def banditReport = readJSON file: 'bandit-report.json'
                        
                        if (banditReport.results.size() > 0) {
                            echo "Bandit found security issues"
                            currentBuild.result = 'UNSTABLE'
                        }
                    } catch (Exception e) {
                        echo "Error in Bandit scan: ${e.message}"
                        currentBuild.result = 'UNSTABLE'
                        // Don't fail the build, continue to next stage
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
                        // Don't fail the build, continue to next stage
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
                        // Fix the filter format
                        bat '''
                            for /F "tokens=*" %%i in ('docker ps -q --filter "name=capstone-devsecops"') do (
                                docker stop %%i 2>nul
                                docker rm %%i 2>nul
                            )
                        '''
                        
                        // Run new container
                        bat "%DOCKER_PATH% run -d --name ${DOCKER_IMAGE}_${BUILD_NUMBER} -p ${APP_PORT}:5000 ${DOCKER_IMAGE}:${DOCKER_TAG}"
                        
                        // Wait for application to start
                        bat "timeout /t 10 /nobreak"
                        
                        // Test if application is running
                        bat "curl http://localhost:${APP_PORT} || echo Application may not be running properly"
                    } catch (Exception e) {
                        echo "Warning: Container execution had issues: ${e.message}"
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
                                case 'HIGH':
                                    highCount++
                                    break
                                case 'MEDIUM':
                                    mediumCount++
                                    break
                                case 'LOW':
                                    lowCount++
                                    break
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
                        archiveArtifacts artifacts: '*-report.json,security-summary.txt', fingerprint: true
                        
                        if (highCount > 0) {
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
                    // Fix the filter format for cleanup
                    bat '''
                        for /F "tokens=*" %%i in ('docker ps -a -q --filter "name=capstone-devsecops"') do (
                            docker stop %%i 2>nul
                            docker rm %%i 2>nul
                        )
                    '''
                } catch (Exception e) {
                    echo "Warning: Container cleanup had issues: ${e.message}"
                }
                cleanWs()
            }
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
