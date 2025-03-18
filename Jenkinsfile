pipeline {
    agent any

    environment {
        DOCKER_IMAGE = 'capstone-devsecops'
        DOCKER_TAG = "${BUILD_NUMBER}"
        DOCKER_PATH = '"C:\\Program Files\\Docker\\Docker\\resources\\bin\\docker.exe"'
        APP_PORT = '5000'
        DOCKER_DESKTOP = true  // Set to true if using Docker Desktop
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
                        archiveArtifacts artifacts: 'bandit-report.json', fingerprint: true
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
                        archiveArtifacts artifacts: 'safety-report.json', fingerprint: true
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
                    // Check if Docker is installed and running
                    try {
                        bat 'where docker || echo "Docker not found"'
                        def dockerPath = bat(script: 'where docker', returnStdout: true).trim()
                        if (dockerPath) {
                            echo "Found Docker at ${dockerPath}"
                            env.DOCKER_PATH = dockerPath
                        } else {
                            echo "Using configured Docker path: ${DOCKER_PATH}"
                        }
                        
                        // Test Docker connection
                        bat "%DOCKER_PATH% --version || echo Docker not running"
                    } catch (Exception e) {
                        error "Docker installation check failed: ${e.message}"
                    }
                }
            }
        }

        stage('Build Docker Image') {
            steps {
                script {
                    try {
                        // Build with explicit Docker path
                        bat "%DOCKER_PATH% build -t ${DOCKER_IMAGE}:${DOCKER_TAG} -f docker/Dockerfile ."
                    } catch (err) {
                        error "Failed to build Docker image: ${err}"
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
                        
                        // Check if HIGH severity field exists and has value
                        if (banditReport.metrics.SEVERITY && banditReport.metrics.SEVERITY.HIGH > 0) {
                            echo "Found ${banditReport.metrics.SEVERITY.HIGH} high severity issues"
                            currentBuild.result = 'UNSTABLE'
                        } else {
                            echo "No high severity issues found"
                        }
                    } catch (Exception e) {
                        echo "Warning: Error analyzing security reports: ${e.message}"
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
        failure {
            echo 'Pipeline failed!'
        }
        unstable {
            echo 'Pipeline is unstable. Security issues may have been found.'
        }
    }
} 
