const execSync = require('child_process').execSync;

try {
  const gitDir = execSync('git rev-parse --show-toplevel').toString().trim();
  if(gitDir !== process.cwd()) {
    console.log(gitDir);
    throw new Error();
  }
  try {
    execSync('git config --local include.path ../.gitconfig');
  } catch(error) {
    console.log('Could not install pre-commit hook');
  }  
} catch(error) {
  console.log('Not running from git clone, ignoring post install');
}
