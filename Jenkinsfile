pipeline {
    agent any

    environment {
        DOCKER_IMAGE = 'capstone-devsecops'
        DOCKER_TAG = "${BUILD_NUMBER}"
        APP_PORT = '5000'
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

        stage('Build Docker Image') {
            steps {
                script {
                    try {
                        bat "docker build -t ${DOCKER_IMAGE}:${DOCKER_TAG} -f docker/Dockerfile ."
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
                        // Run new container
                        bat "docker run -d --name ${DOCKER_IMAGE}_${BUILD_NUMBER} -p 5000:5000 ${DOCKER_IMAGE}:${DOCKER_TAG}"
                        
                        // Wait for application to start
                        bat "timeout 10"
                        
                        // Test if application is running
                        bat "curl http://localhost:5000"
                    } catch (err) {
                        error "Failed to run container: ${err}"
                    }
                }
            }
        }

        stage('Security Report Analysis') {
            steps {
                script {
                    def banditReport = readJSON file: 'bandit-report.json'
                    if (banditReport.metrics.SEVERITY.HIGH > 0) {
                        error "High severity issues found in SAST scan"
                    }
                }
            }
        }
    }

    post {
        always {
            script {
                // Cleanup containers
                bat """
                    docker ps -q --filter name=${DOCKER_IMAGE} | findstr . && docker stop ${DOCKER_IMAGE}_${BUILD_NUMBER} || echo No container running
                    docker ps -aq --filter name=${DOCKER_IMAGE} | findstr . && docker rm ${DOCKER_IMAGE}_${BUILD_NUMBER} || echo No container to remove
                """
            }
            cleanWs()
        }
        success {
            echo 'Pipeline completed successfully!'
        }
        failure {
            echo 'Pipeline failed!'
        }
    }
} 
