<h1>🚨 SSH Brute-Force Log Analyzer</h1>

<p>
A simple Python tool that analyzes Linux <code>auth.log</code> files to detect SSH brute-force 
login attacks. The project includes both a <strong>CLI version</strong> and a 
<strong>GUI version</strong> built using Tkinter.
</p>

<hr>

<h2>✨ Features</h2>
<ul>
    <li>Detects repeated failed SSH login attempts</li>
    <li>Classifies severity (Low / Medium / High)</li>
    <li>Extracts IP address, timestamp, and attack time window</li>
    <li>Generates a structured JSON report</li>
    <li>GUI version with file browser and easy controls</li>
</ul>

<hr>

<h2>🚀 How to Run</h2>

<h3>CLI Version</h3>
<pre>
<code>python analyzer.py --log logs/auth.log</code>
</pre>

<h3>GUI Version</h3>
<pre>
<code>python gui.py</code>
</pre>

<hr>

<h2>📄 Output Includes</h2>
<ul>
    <li>Suspicious IP addresses</li>
    <li>Number of failed login attempts</li>
    <li>Severity level</li>
    <li>Suggested security action</li>
    <li>JSON report saved in <code>reports/report.json</code></li>
</ul>

<hr>

<h2>🛠 Technologies Used</h2>
<ul>
    <li>Python</li>
    <li>Regex (pattern matching)</li>
    <li>Tkinter (GUI)</li>
    <li>JSON</li>
</ul>
