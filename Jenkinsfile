pipeline {
    agent any

    environment {
        DOCKER_IMAGE = 'capstone-devsecops'
        DOCKER_TAG = "${BUILD_NUMBER}"
    }

    stages {
        stage('Checkout') {
            steps {
                checkout scm
            }
        }

        stage('Install Dependencies') {
            steps {
                sh 'python -m pip install --upgrade pip'
                sh 'pip install -r requirements.txt'
            }
        }

        stage('Run Tests') {
            steps {
                sh 'python -m pytest tests/'
            }
        }

        stage('SAST - Bandit Scan') {
            steps {
                script {
                    try {
                        sh '''
                            bandit -r . -f json -o bandit-report.json
                            bandit -r . -f html -o bandit-report.html
                        '''
                    } catch (err) {
                        echo "Bandit found security issues"
                        currentBuild.result = 'UNSTABLE'
                    }
                }
                archiveArtifacts artifacts: 'bandit-report.*', fingerprint: true
            }
        }

        stage('SCA - Safety Check') {
            steps {
                script {
                    try {
                        sh 'safety check --json > safety-report.json'
                        sh 'safety check --output text > safety-report.txt'
                    } catch (err) {
                        echo "Safety found dependency issues"
                        currentBuild.result = 'UNSTABLE'
                    }
                }
                archiveArtifacts artifacts: 'safety-report.*', fingerprint: true
            }
        }

        stage('Build Docker Image') {
            steps {
                script {
                    docker.build("${DOCKER_IMAGE}:${DOCKER_TAG}", "-f docker/Dockerfile .")
                }
            }
        }

        stage('Security Report Analysis') {
            steps {
                script {
                    def banditReport = readJSON file: 'bandit-report.json'
                    def safetyReport = readJSON file: 'safety-report.json'
                    
                    def highSeverityIssues = banditReport.metrics.SEVERITY.HIGH ?: 0
                    
                    if (highSeverityIssues > 0) {
                        error "Found ${highSeverityIssues} high severity issues in SAST scan"
                    }
                }
            }
        }
    }

    post {
        always {
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