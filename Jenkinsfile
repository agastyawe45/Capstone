pipeline {
    agent any

    environment {
        SLACK_CHANNEL = '#jenkins-notifications'
        SLACK_TOKEN = credentials('slack-token')
        PYTHON_PATH = 'C:\\Python312\\python.exe'
    }

    options {
        timestamps()  // Add timestamps to console output
        timeout(time: 30, unit: 'MINUTES')  // Global timeout
        buildDiscarder(logRotator(numToKeepStr: '10'))  // Keep only last 10 builds
        disableConcurrentBuilds()  // Prevent concurrent executions
    }

    stages {
        stage('Checkout') {
            steps {
                cleanWs()
                checkout scm
            }
        }

        stage('Setup Python Environment') {
            steps {
                script {
                    bat '''
                        python -m venv venv
                        call venv\\Scripts\\activate.bat
                        python -m pip install --upgrade pip
                        pip install -r requirements.txt
                    '''
                }
            }
        }

        stage('SAST - Bandit Security Scan') {
            steps {
                script {
                    try {
                        bat '''
                            call venv\\Scripts\\activate.bat
                            bandit -r . -f json -o bandit-report.json -ll
                            bandit -r . -f html -o bandit-report.html -ll
                        '''
                        
                        def banditReport = readJSON file: 'bandit-report.json'
                        def metrics = banditReport.metrics ?: [:]
                        def severity = metrics.SEVERITY ?: [:]
                        
                        def highSeverityCount = severity.HIGH ?: 0
                        def mediumSeverityCount = severity.MEDIUM ?: 0
                        def lowSeverityCount = severity.LOW ?: 0
                        
                        def severityEmoji = highSeverityCount > 0 ? "🚨" : (mediumSeverityCount > 0 ? "⚠️" : "✅")
                        def messageColor = highSeverityCount > 0 ? "danger" : (mediumSeverityCount > 0 ? "warning" : "good")
                        
                        // Enhanced SAST reporting with remediation guidance
                        slackSend(
                            channel: env.SLACK_CHANNEL,
                            color: messageColor,
                            message: """
                            ${severityEmoji} *SAST Scan Results*
                            - High Severity: ${highSeverityCount}
                            - Medium Severity: ${mediumSeverityCount}
                            - Low Severity: ${lowSeverityCount}
                            - Full Report: ${env.BUILD_URL}artifact/bandit-report.html
                            
                            ${highSeverityCount > 0 ? '''🚨 *Critical Security Issues Found:*
                            - Review high-severity findings immediately
                            - Follow secure coding guidelines
                            - Update vulnerable code patterns''' : ''}
                            """
                        )
                        
                        if (highSeverityCount > 0) {
                            unstable('High severity security issues found')
                        }
                    } catch (Exception e) {
                        handleScanError('SAST', e)
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
                            pip install pyraider
                            pyraider scan > pyraider-report.json
                        '''
                        
                        def pyraiderReport = readJSON file: 'pyraider-report.json'
                        def vulnerabilityCount = pyraiderReport.size() ?: 0
                        
                        def messageColor = vulnerabilityCount > 0 ? 'warning' : 'good'
                        def statusEmoji = vulnerabilityCount > 0 ? '⚠️' : '✅'
                        
                        slackSend(
                            channel: env.SLACK_CHANNEL,
                            color: messageColor,
                            message: """
                            ${statusEmoji} *SCA (Pyraider) Results*
                            - Vulnerabilities Found: ${vulnerabilityCount}
                            - Details: ${env.BUILD_URL}artifact/pyraider-report.json
                            
                            ${vulnerabilityCount > 0 ? '''⚠️ *Remediation Steps:*
                            1. Update vulnerable dependencies
                            2. Review dependency changelog
                            3. Test application after updates''' : ''}
                            """
                        )
                        
                        if (vulnerabilityCount > 0) {
                            unstable('Vulnerable dependencies found')
                        }
                    } catch (Exception e) {
                        handleScanError('SCA', e)
                    }
                }
            }
        }

        stage('Documentation and Reports') {
            steps {
                script {
                    try {
                        // Generate documentation
                        bat '''
                            call venv\\Scripts\\activate.bat
                            pdoc3 --html --output-dir docs app/
                            echo "# Pipeline Documentation" > pipeline-docs.md
                            echo "## Build Information" >> pipeline-docs.md
                            echo "- Build Number: ${BUILD_NUMBER}" >> pipeline-docs.md
                            echo "- Build Date: ${BUILD_TIMESTAMP}" >> pipeline-docs.md
                            echo "## Security Scan Results" >> pipeline-docs.md
                            type security-report.md >> pipeline-docs.md
                        '''

                        // Combine security reports
                        def banditReport = readJSON file: 'bandit-report.json'
                        def pyraiderReport = readJSON file: 'pyraider-report.json'
                        
                        def finalReport = """
                            # Security Analysis Report
                            
                            ## Overview
                            - Job: ${env.JOB_NAME}
                            - Build: ${env.BUILD_NUMBER}
                            - Date: ${new Date().format('yyyy-MM-dd HH:mm:ss')}
                            
                            ## SAST Results (Bandit)
                            ${generateSastSummary(banditReport)}
                            
                            ## SCA Results (Pyraider)
                            ${generateScaSummary(pyraiderReport)}
                            
                            ## Remediation Guidelines
                            ${generateRemediationSteps(banditReport, pyraiderReport)}
                        """
                        
                        writeFile file: 'security-report.md', text: finalReport
                        archiveReports()
                        
                    } catch (Exception e) {
                        handleScanError('Documentation', e)
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
                - Documentation: ${env.BUILD_URL}artifact/docs/
                - Security Report: ${env.BUILD_URL}artifact/security-report.md
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
                
                *Required Actions:*
                1. Review security findings
                2. Update vulnerable dependencies
                3. Fix identified code issues
                4. Re-run pipeline after fixes
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

// Helper function for SAST summary generation
def generateSastSummary(def report) {
    def metrics = report.metrics ?: [:]
    def severity = metrics.SEVERITY ?: [:]
    def results = report.results ?: []
    
    def summary = """
    ### SAST Analysis Details
    
    #### Severity Counts
    - High: ${severity.HIGH ?: 0}
    - Medium: ${severity.MEDIUM ?: 0}
    - Low: ${severity.LOW ?: 0}
    
    #### Key Findings
    ${results.collect { finding ->
        """
        * **${finding.issue_severity?.toUpperCase() ?: 'UNKNOWN'} Severity**: ${finding.issue_text ?: 'No description'}
          - Location: ${finding.filename ?: 'Unknown file'}:${finding.line_number ?: 0}
          - CWE: ${finding.issue_cwe?.id ?: 'N/A'}
          - Confidence: ${finding.issue_confidence ?: 'Unknown'}
        """
    }.join('\n')}
    
    #### Scan Statistics
    - Total files analyzed: ${metrics.FILENAME?.count ?: 0}
    - Lines of code scanned: ${metrics.LOC?.count ?: 0}
    - Skipped files: ${metrics.SKIPPED?.count ?: 0}
    """
    
    return summary
}

// Helper function for SCA summary generation
def generateScaSummary(def report) {
    def vulnerabilities = report ?: []
    
    def summary = """
    ### Software Composition Analysis Results
    
    #### Vulnerability Summary
    Total vulnerabilities found: ${vulnerabilities.size()}
    
    #### Detailed Findings
    ${vulnerabilities.collect { vuln ->
        """
        * **Package**: ${vuln.package_name ?: 'Unknown'}
          - Current Version: ${vuln.installed_version ?: 'Unknown'}
          - Fixed Version: ${vuln.fixed_version ?: 'Not specified'}
          - Severity: ${vuln.severity ?: 'Unknown'}
          - CVE: ${vuln.cve_id ?: 'N/A'}
          - Description: ${vuln.description ?: 'No description available'}
        """
    }.join('\n')}
    """
    
    return summary
}

// Helper function for generating remediation steps
def generateRemediationSteps(def sastReport, def scaReport) {
    def highSeverityIssues = (sastReport.results ?: []).findAll { it.issue_severity == 'HIGH' }
    def vulnerablePackages = scaReport ?: []
    
    def remediation = """
    ### Remediation Guidelines
    
    #### Critical Security Issues
    ${highSeverityIssues.collect { issue ->
        """
        * **${issue.issue_text}**
          - Location: ${issue.filename}:${issue.line_number}
          - Recommendation: ${getRecommendation(issue.issue_text)}
          - Best Practice: ${getBestPractice(issue.issue_text)}
        """
    }.join('\n')}
    
    #### Vulnerable Dependencies
    ${vulnerablePackages.collect { vuln ->
        """
        * **${vuln.package_name}**
          - Current: ${vuln.installed_version}
          - Recommended: ${vuln.fixed_version ?: 'Latest stable version'}
          - Action: Update package using `pip install ${vuln.package_name}==${vuln.fixed_version ?: 'latest'}`
        """
    }.join('\n')}
    
    #### General Security Guidelines
    1. **Input Validation**
       - Implement strict input validation for all user inputs
       - Use parameterized queries for database operations
       - Sanitize all user-supplied data
    
    2. **Authentication & Authorization**
       - Implement proper session management
       - Use secure password hashing (e.g., bcrypt)
       - Apply principle of least privilege
    
    3. **Dependency Management**
       - Regularly update dependencies
       - Monitor security advisories
       - Maintain a dependency inventory
    
    4. **Code Security**
       - Follow secure coding guidelines
       - Implement proper error handling
       - Use security headers
       - Enable HTTPS
    
    5. **Monitoring & Logging**
       - Implement comprehensive logging
       - Monitor application behavior
       - Set up alerts for suspicious activities
    """
    
    return remediation
}

// Helper function for getting security recommendations
def getRecommendation(String issueText) {
    def recommendations = [
        'hardcoded_password': 'Use environment variables or secure credential storage',
        'sql_injection': 'Use parameterized queries or ORM',
        'command_injection': 'Use safe APIs or input validation',
        'xss': 'Implement proper output encoding',
        'csrf': 'Implement CSRF tokens',
        'default': 'Review and apply security best practices'
    ]
    
    return recommendations.find { issue, _ -> 
        issueText.toLowerCase().contains(issue)
    }?.value ?: recommendations.default
}

// Helper function for security best practices
def getBestPractice(String issueText) {
    def bestPractices = [
        'password': '''
            - Use strong password policies
            - Implement MFA where possible
            - Store passwords using secure hashing
        ''',
        'injection': '''
            - Validate all inputs
            - Use prepared statements
            - Implement WAF protection
        ''',
        'default': '''
            - Follow OWASP security guidelines
            - Implement defense in depth
            - Regular security training
        '''
    ]
    
    return bestPractices.find { issue, _ ->
        issueText.toLowerCase().contains(issue)
    }?.value ?: bestPractices.default
}

// Helper function for error handling with detailed reporting
def handleScanError(String scanType, Exception e) {
    def errorDetails = """
    ### Error Details
    - Scan Type: ${scanType}
    - Error Message: ${e.message}
    - Stack Trace: ${e.stackTrace.join('\n')}
    
    ### Troubleshooting Steps
    1. Check environment setup
    2. Verify tool installation
    3. Review permissions
    4. Check network connectivity
    
    ### Contact Information
    Please contact the security team for assistance.
    """
    
    // Add error metrics
    def errorMetrics = """
    ### Error Metrics
    - Timestamp: ${new Date().format('yyyy-MM-dd HH:mm:ss')}
    - Stage Duration: ${currentBuild.durationString}
    - Previous Status: ${currentBuild.previousBuild?.result ?: 'N/A'}
    - Failure Count: ${currentBuild.previousBuild?.result == 'FAILURE' ? 'Consecutive failure' : 'First failure'}
    
    ### System Information
    - Jenkins Version: ${Jenkins.instance.version}
    - Node Name: ${env.NODE_NAME}
    - Workspace: ${env.WORKSPACE}
    """
    
    // Append to error report
    writeFile file: "${scanType.toLowerCase()}-error-report.txt", 
             text: errorDetails + "\n" + errorMetrics
    
    slackSend(
        channel: env.SLACK_CHANNEL,
        color: 'danger',
        message: """
        ❌ *${scanType} Scan Failed*
        - Error: ${e.message}
        - Job: ${env.JOB_NAME} #${env.BUILD_NUMBER}
        - Error Report: ${env.BUILD_URL}artifact/${scanType.toLowerCase()}-error-report.txt
        - Console Output: ${env.BUILD_URL}console
        
        *Immediate Actions Required:*
        1. Review error report
        2. Check scan configuration
        3. Verify tool dependencies
        """
    )
    
    unstable("${scanType} scan failed but continuing pipeline")
}

// Add after Checkout stage
stage('Verify Tools') {
    steps {
        script {
            bat '''
                python --version
                pip --version
                bandit --version
                pyraider --version
            '''
        }
    }
}

// Add to Environment Setup stage
steps {
    script {
        if (!fileExists('requirements.txt')) {
            error('requirements.txt not found!')
        }
        // ... existing setup steps ...
    }
}

// Add to SAST and SCA stages
timeout(time: 10, unit: 'MINUTES') {
    // existing stage steps
}

// Add to Documentation and Reports stage
def archiveReports() {
    // Create reports directory
    bat 'mkdir reports || exit 0'
    
    // Move all reports to reports directory
    bat '''
        move bandit-report.* reports\\
        move pyraider-report.* reports\\
        move security-report.md reports\\
        move *-error-report.txt reports\\ 2>nul || exit 0
    '''
    
    // Archive with better organization
    archiveArtifacts artifacts: '''
        reports/**/*,
        docs/**/*,
        test-results.xml
    ''', fingerprint: true
}

environment {
    // Add these to existing environment block
    BUILD_TIMESTAMP = new Date().format('yyyy-MM-dd_HH-mm-ss')
    REPORTS_DIR = "reports_${BUILD_TIMESTAMP}"
    TEST_RESULTS_PATH = 'test-results.xml'
    PYTHON_VERSION = '3.12'  // Specify Python version explicitly
}

// Add this function at the end of the file for centralized Slack messaging
def sendDetailedSlackNotification(String stage, String status, String color, Map details) {
    def headerEmoji = [
        'SUCCESS': '✅',
        'UNSTABLE': '⚠️',
        'FAILURE': '❌',
        'SECURITY': '🔒',
        'WARNING': '⚡',
        'INFO': 'ℹ️'
    ]
    
    def timestamp = new Date().format("yyyy-MM-dd HH:mm:ss")
    def duration = currentBuild.durationString.replace(' and counting', '')
    
    def message = """
    ${headerEmoji[status]} *${stage} - ${status}*
    
    *Build Information*
    • Job: ${env.JOB_NAME}
    • Build: <${env.BUILD_URL}|#${env.BUILD_NUMBER}>
    • Branch: ${env.GIT_BRANCH ?: 'N/A'}
    • Commit: ${env.GIT_COMMIT ? env.GIT_COMMIT[0..7] : 'N/A'}
    • Duration: ${duration}
    • Time: ${timestamp}
    
    ${details.collect { key, value -> 
        "*${key}*\n${value.split('\n').collect { "• ${it}" }.join('\n')}"
    }.join('\n\n')}
    
    ${details.containsKey('Actions Required') ? '''
    🔍 *Quick Links*
    • <${env.BUILD_URL}console|Console Output>
    • <${env.BUILD_URL}artifact|Artifacts>
    • <${env.BUILD_URL}testReport|Test Report>
    ''' : ''}
    """
    
    slackSend(channel: env.SLACK_CHANNEL, color: color, message: message)
}

// Update the stages with enhanced notifications:

// Checkout stage notification
stage('Checkout') {
    // ... existing checkout steps ...
    post {
        success {
            script {
                sendDetailedSlackNotification(
                    'Source Code Checkout',
                    'SUCCESS',
                    'good',
                    [
                        'Repository Details': """
                            Repository: ${env.GIT_URL ?: 'N/A'}
                            Branch: ${env.GIT_BRANCH ?: 'N/A'}
                            Commit: ${env.GIT_COMMIT ?: 'N/A'}
                            Author: ${sh(script: 'git log -1 --pretty=format:"%an"', returnStdout: true).trim()}
                            Message: ${sh(script: 'git log -1 --pretty=format:"%s"', returnStdout: true).trim()}
                        """
                    ]
                )
            }
        }
    }
}

// Unit Tests stage notification
stage('Run Unit Tests') {
    // ... existing test steps ...
    post {
        always {
            script {
                def testResults = junit testResults: 'test-results.xml', allowEmptyResults: true
                
                sendDetailedSlackNotification(
                    'Unit Tests',
                    testResults.failCount == 0 ? 'SUCCESS' : 'FAILURE',
                    testResults.failCount == 0 ? 'good' : 'danger',
                    [
                        'Test Results': """
                            Total Tests: ${testResults.totalCount}
                            Passed: ${testResults.passCount}
                            Failed: ${testResults.failCount}
                            Skipped: ${testResults.skipCount}
                            Success Rate: ${Math.round((testResults.passCount / testResults.totalCount) * 100)}%
                        """,
                        'Actions Required': testResults.failCount > 0 ? 'Review failed tests in the test report' : null
                    ]
                )
            }
        }
    }
}

// SAST stage notification enhancement
stage('SAST - Bandit Security Scan') {
    // ... existing SAST steps ...
    post {
        always {
            script {
                def banditReport = readJSON file: 'bandit-report.json'
                def metrics = banditReport.metrics ?: [:]
                def severity = metrics.SEVERITY ?: [:]
                
                def highCount = severity.HIGH ?: 0
                def mediumCount = severity.MEDIUM ?: 0
                def lowCount = severity.LOW ?: 0
                
                def totalIssues = highCount + mediumCount + lowCount
                def riskLevel = highCount > 0 ? 'HIGH' : (mediumCount > 0 ? 'MEDIUM' : 'LOW')
                
                sendDetailedSlackNotification(
                    'SAST Security Scan',
                    totalIssues > 0 ? 'WARNING' : 'SUCCESS',
                    totalIssues > 0 ? (highCount > 0 ? 'danger' : 'warning') : 'good',
                    [
                        'Scan Results': """
                            Total Issues: ${totalIssues}
                            High Severity: ${highCount}
                            Medium Severity: ${mediumCount}
                            Low Severity: ${lowCount}
                            Risk Level: ${riskLevel}
                        """,
                        'Scan Coverage': """
                            Files Scanned: ${metrics.FILENAME?.count ?: 0}
                            Lines of Code: ${metrics.LOC?.count ?: 0}
                            Skipped Files: ${metrics.SKIPPED?.count ?: 0}
                        """,
                        'Actions Required': totalIssues > 0 ? """
                            1. Review security findings in the report
                            2. Address high-severity issues immediately
                            3. Plan remediation for medium/low severity issues
                            4. Update security documentation
                        """ : null
                    ]
                )
            }
        }
    }
}

// SCA stage notification enhancement
stage('SCA - Pyraider Security Check') {
    // ... existing SCA steps ...
    post {
        always {
            script {
                def pyraiderReport = readJSON file: 'pyraider-report.json'
                def vulnerabilities = pyraiderReport ?: []
                
                def severityCounts = vulnerabilities.groupBy { it.severity }.collectEntries { 
                    [(it.key): it.value.size()] 
                }
                
                sendDetailedSlackNotification(
                    'Dependencies Security Check',
                    vulnerabilities.size() > 0 ? 'WARNING' : 'SUCCESS',
                    vulnerabilities.size() > 0 ? 'warning' : 'good',
                    [
                        'Vulnerability Summary': """
                            Total Vulnerabilities: ${vulnerabilities.size()}
                            Critical: ${severityCounts['CRITICAL'] ?: 0}
                            High: ${severityCounts['HIGH'] ?: 0}
                            Medium: ${severityCounts['MEDIUM'] ?: 0}
                            Low: ${severityCounts['LOW'] ?: 0}
                        """,
                        'Affected Packages': vulnerabilities.size() > 0 ? 
                            vulnerabilities.collect { "${it.package_name} (${it.installed_version})" }.join('\n') : 
                            'No vulnerable packages found',
                        'Actions Required': vulnerabilities.size() > 0 ? """
                            1. Update vulnerable dependencies
                            2. Review dependency changelog
                            3. Run regression tests after updates
                            4. Document any required application changes
                        """ : null
                    ]
                )
            }
        }
    }
}

// Final pipeline status notification enhancement
post {
    success {
        script {
            sendDetailedSlackNotification(
                'Pipeline Execution',
                'SUCCESS',
                'good',
                [
                    'Build Summary': """
                        All stages completed successfully
                        Duration: ${currentBuild.durationString}
                        Artifacts generated and archived
                    """,
                    'Security Status': """
                        SAST Scan: Completed
                        SCA Scan: Completed
                        Reports Available in Build Artifacts
                    """
                ]
            )
        }
    }
    unstable {
        script {
            sendDetailedSlackNotification(
                'Pipeline Execution',
                'UNSTABLE',
                'warning',
                [
                    'Build Summary': """
                        Pipeline completed with warnings
                        Duration: ${currentBuild.durationString}
                    """,
                    'Security Concerns': """
                        Security issues detected
                        Review security reports for details
                    """,
                    'Actions Required': """
                        1. Review security findings
                        2. Address identified vulnerabilities
                        3. Update dependencies if needed
                        4. Re-run pipeline after fixes
                    """
                ]
            )
        }
    }
    failure {
        script {
            sendDetailedSlackNotification(
                'Pipeline Execution',
                'FAILURE',
                'danger',
                [
                    'Build Summary': """
                        Pipeline failed
                        Duration: ${currentBuild.durationString}
                        Stage: ${currentBuild.result}
                    """,
                    'Error Information': """
                        Check console output for detailed error logs
                        Last successful build: ${currentBuild.previousSuccessfulBuild?.displayName ?: 'None'}
                    """,
                    'Actions Required': """
                        1. Review error logs
                        2. Fix identified issues
                        3. Verify environment setup
                        4. Re-run pipeline
                    """
                ]
            )
        }
    }
} 
