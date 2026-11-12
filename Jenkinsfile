pipeline {
    agent any
    stages {
        stage('Build')  { steps { sh 'mvn -B clean package' } }
        stage('Docker') { steps { sh 'docker build -t website-monitor .' } }
    }
}