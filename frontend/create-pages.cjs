const fs = require('fs');
const path = require('path');
const pages = ['Dashboard', 'Repository', 'LiveScan', 'Vulnerabilities', 'AIAgent', 'BusinessRisk', 'Compliance', 'PredictiveAnalytics', 'Reports', 'Settings'];
const dir = path.join(__dirname, 'src', 'pages');

pages.forEach(p => {
  const content = `export default function ${p}() {
  return (
    <div className="p-6">
      <h1 className="text-2xl font-heading font-bold mb-4">${p}</h1>
      <div className="glass-card p-6 min-h-[400px]">
        <p className="text-slate-400">Placeholder for ${p} view.</p>
      </div>
    </div>
  );
}`;
  fs.writeFileSync(path.join(dir, `${p}.jsx`), content);
});
console.log('Pages created.');
