// Jenkinsfile - Pipeline de "Sistema Alumnos" (SecureDev · Evaluación Parcial 3 · OCY1102)
//
// Build -> Test -> Security Review (SAST) -> Dependency Management -> Deploy Staging
//       -> DAST (OWASP ZAP) -> Deploy Producción (solo si todo está limpio)
pipeline {
    agent any

    options {
        timestamps()
        timeout(time: 40, unit: 'MINUTES')
        disableConcurrentBuilds()
    }

    // Revisa GitHub cada ~3 minutos: cada push (tuyo o un PR de Dependabot fusionado) dispara un build.
    triggers {
        pollSCM('H/3 * * * *')
    }

    environment {
        PIP_DISABLE_PIP_VERSION_CHECK = '1'
    }

    stages {
        stage('Build') {
            steps {
                script {
                    // Versión = 1.0.<nº de build>+<commit corto>: une cada despliegue con su commit (trazabilidad)
                    def sha = sh(returnStdout: true, script: 'git rev-parse --short HEAD').trim()
                    env.APP_VERSION = "1.0.${env.BUILD_NUMBER}+${sha}"
                }
                echo "Versión de este build: ${env.APP_VERSION}"
                sh 'git log -1 --format="Commit %h de %an: %s"'
                // Cada build parte limpio: sin reportes viejos y con un entorno virtual nuevo
                sh 'rm -rf .venv reports && mkdir -p reports'
                sh 'python3 -m venv .venv'
                sh '.venv/bin/pip install --quiet -r requirements.txt -r requirements-dev.txt'
                sh '.venv/bin/python -m compileall -q app.py'
            }
        }

        stage('Test') {
            steps {
                sh '.venv/bin/python -m pytest --junitxml=reports/junit.xml'
            }
            post {
                always {
                    junit allowEmptyResults: true, testResults: 'reports/junit.xml'
                }
            }
        }

        // ---- Revisiones de seguridad continuas ----------------------------------------
        stage('Security Review (SAST)') {
            steps {
                // reports/bandit.json lo lee scripts/trazabilidad.py; bandit.txt es el reporte legible
                catchError(buildResult: 'UNSTABLE', stageResult: 'UNSTABLE') {
                    sh '''#!/bin/bash
set -o pipefail
bandit -r app.py -f json -o reports/bandit.json || true
bandit -r app.py -ll | tee reports/bandit.txt
'''
                }
            }
        }

        stage('Dependency Management') {
            steps {
                // reports/pip-audit.json lo lee scripts/trazabilidad.py; pip-audit.txt es el reporte legible
                catchError(buildResult: 'UNSTABLE', stageResult: 'UNSTABLE') {
                    sh '''#!/bin/bash
set -o pipefail
pip-audit -r requirements.txt -f json -o reports/pip-audit.json || true
pip-audit -r requirements.txt | tee reports/pip-audit.txt
'''
                }
            }
        }

        // ---- Pruebas dinámicas sobre un entorno de staging (nunca sobre producción) ----------------
        stage('Deploy Staging') {
            steps {
                sh 'bash scripts/deploy.sh staging 5001'
            }
        }

        stage('DAST - OWASP ZAP') {
            steps {
                timeout(time: 15, unit: 'MINUTES') {
                    script {
                        // zap_scan.py termina con código 2 si hay alertas High/Medium
                        def codigo = sh(returnStatus: true, script: 'python3 scripts/zap_scan.py http://jenkins:5001')
                        if (codigo == 2) {
                            unstable('OWASP ZAP encontró alertas High/Medium')
                        } else if (codigo != 0) {
                            error("El escaneo de ZAP falló (código ${codigo})")
                        }
                    }
                }
            }
        }

        stage('Deploy Producción') {
            // Gate: solo se despliega a producción si no hubo hallazgos en las etapas anteriores
            when {
                expression { currentBuild.currentResult == 'SUCCESS' }
            }
            steps {
                sh 'bash scripts/deploy.sh produccion 5000'
                script { env.PRODUCCION = env.APP_VERSION }
            }
        }
    }

    post {
        always {
            // Registro de trazabilidad: build <-> versión <-> commit <-> pruebas <-> hallazgos <-> despliegue
            withEnv(["RESULTADO=${currentBuild.currentResult}"]) {
                sh 'python3 scripts/trazabilidad.py'
            }
            archiveArtifacts artifacts: 'reports/**', allowEmptyArchive: true
        }
    }
}