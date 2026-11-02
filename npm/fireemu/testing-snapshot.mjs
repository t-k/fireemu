// Snapshot caller-owned input once; each generation gets its own writable copy.
import { constants } from 'node:fs';
import { cp, mkdir, readFile, writeFile, realpath, symlink, lstat, stat, unlink, readdir, readlink } from 'node:fs/promises';
import { basename, dirname, join, resolve, relative, sep, delimiter, isAbsolute } from 'node:path';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { resolveBinary, ensureExecutable } from './binary.mjs';

const runFile = promisify(execFile);

async function readConfiguration(path, options) {
  const format = path.toLowerCase().endsWith('.toml') ? 'TOML' : 'JSON';
  try {
    if (format === 'JSON') return JSON.parse(await readFile(path, 'utf8'));
    const binary = resolveBinary(options.binaryPath ? resolve(options.binaryPath) : undefined);
    if (!binary) throw Error('install the fireemu platform package or supply binaryPath');
    ensureExecutable(binary.path);
    // Use the CLI parser so TOML types and rejection rules cannot drift between callers.
    const { stdout } = await runFile(binary.path, ['__test-world-config', path], {
      encoding: 'utf8', windowsHide: true, timeout: options.startupTimeoutMs ?? 60_000,
      killSignal: 'SIGKILL', maxBuffer: 16 * 1024 * 1024, signal: options.signal,
    });
    return JSON.parse(stdout);
  } catch (cause) {
    throw Error(`Cannot read ${format} configuration ${JSON.stringify(path)}: ${cause.stderr?.trim() || cause.message}`, { cause });
  }
}

export async function snapshotInputs(options, root) {
  const cwd=resolve(options.cwd??process.cwd());
  const nodePathExcludes=options.nodePathExcludes===undefined?[]:options.nodePathExcludes;
  const packageName=value=>{
    if(typeof value!=='string'||value.includes('\\')||value.includes('\0'))return false;
    const parts=value.split('/');
    return (value.startsWith('@')?parts.length===2&&parts[0].length>1:parts.length===1)
      &&parts.every((part,index)=>part!=='.'&&part!=='..'&&/^[a-zA-Z0-9._~-]+$/.test(index===0&&value.startsWith('@')?part.slice(1):part));
  };
  if(!Array.isArray(nodePathExcludes)||!nodePathExcludes.every(packageName))throw TypeError('nodePathExcludes must be an array of unscoped or scoped package names');
  const privateRoot=await realpath(root);
  const baseline=join(root,'baseline');
  await mkdir(baseline,{mode:0o700});
  let sequence=0;
  const copyFile=async(value,base)=>{
    if(typeof value!=='string')return value;
    const destination=join(baseline,`input-${sequence++}-${basename(value)}`);
    await cp(resolve(base,value),destination,{recursive:true,mode:constants.COPYFILE_FICLONE,dereference:true});
    return destination;
  };
  const graph=new Map();
  const inside=(parent,path)=>{const suffix=relative(parent,path);return suffix===''||(!suffix.startsWith(`..${sep}`)&&suffix!=='..'&&!isAbsolute(suffix));};
  const omitted=new Set();
  const captureTree=async(source,destination,excludes=[])=>{
    try{
      const canonical=await realpath(source);
      graph.set(canonical,destination);
      const links=[];
      await cp(canonical,destination,{recursive:true,mode:constants.COPYFILE_FICLONE,dereference:false,verbatimSymlinks:true,filter:async(path,target)=>{
        if(excludes.includes(path)){omitted.add(path);return false;}
        if(['.git','.worktree'].includes(basename(path)))return false;
        if((await lstat(path)).isSymbolicLink())links.push([path,target]);
        return true;
      }});
      for(const [sourceLink,targetLink] of links){
        let linkValue;
        try{
          linkValue=await readlink(sourceLink);
          const target=await realpath(sourceLink);
          const linkedExcludes=excludes.filter(path=>inside(sourceLink,path)).map(path=>join(target,relative(sourceLink,path)));
          if([...omitted].some(path=>inside(path,target)))throw Error(`Retained link ${JSON.stringify(sourceLink)} requires excluded NODE_PATH package content ${JSON.stringify(target)}; remove that package from nodePathExcludes`);
          let copied;
          const owners=[...graph].filter(([original])=>inside(original,target)).sort((a,b)=>b[0].length-a[0].length);
          if(owners.length&&linkedExcludes.length)throw Error(`Cannot apply nodePathExcludes through linked scope ${JSON.stringify(sourceLink)}: target ${JSON.stringify(target)} was already captured; narrow env.NODE_PATH instead`);
          if(owners.length){const [original,snapshot]=owners[0];copied=join(snapshot,relative(original,target));}
          else{
            if(graph.size>=4096)throw Error('Functions dependency graph exceeds the snapshot budget');
            // pnpm packages resolve dependencies from their enclosing node_modules,
            // including siblings that are not explicit links inside the package.
            let context=dirname(target);
            while(basename(context)!=='node_modules'&&dirname(context)!==context)context=dirname(context);
            if(basename(context)!=='node_modules')context=target;
            const destination=join(baseline,`linked-${sequence++}`,...(basename(context)==='node_modules'?['node_modules']:[]));
            await captureTree(context,destination,linkedExcludes);
            copied=join(destination,relative(context,target));
          }
          await unlink(targetLink);
          const kind=(await lstat(target)).isDirectory()?'dir':'file';
          await symlink(process.platform==='win32'?copied:relative(dirname(targetLink),copied),targetLink,process.platform==='win32'&&kind==='dir'?'junction':kind);
        }catch(cause){
          throw Error(`Cannot snapshot dependency link ${JSON.stringify(sourceLink)} -> ${JSON.stringify(linkValue)}: ${cause.message}`,{cause});
        }
      }
    }catch(cause){
      throw Error(`Cannot snapshot dependency tree ${JSON.stringify(source)}: ${cause.message}`,{cause});
    }
  };
  const copySource=async(value,base)=>{
    if(typeof value!=='string')return value;
    const source=await realpath(resolve(base,value));
    if(inside(source,privateRoot))throw Error('world temporary directory must be outside the Functions source');
    const dependencies=[];
    for(let ancestor=dirname(source),level=1;;ancestor=dirname(ancestor),level++){
      const modules=join(ancestor,'node_modules');
      try{if((await stat(modules)).isDirectory())dependencies.push({modules,level});}catch(error){if(error.code!=='ENOENT')throw error;}
      if(dirname(ancestor)===ancestor)break;
    }
    const container=join(baseline,`functions-${sequence++}`);
    const depth=dependencies.at(-1)?.level??0;
    const destination=join(container,...Array(depth).fill('source'));
    await captureTree(source,destination);
    for(const {modules,level} of dependencies){
      let ancestor=destination;for(let count=0;count<level;count++)ancestor=dirname(ancestor);
      const target=join(ancestor,'node_modules'),canonical=await realpath(modules);
      if(graph.has(canonical))await symlink(process.platform==='win32'?graph.get(canonical):relative(ancestor,graph.get(canonical)),target,process.platform==='win32'?'junction':'dir');
      else await captureTree(modules,target);
    }
    return destination;
  };
  const snapshotFirebase=async(input,base)=>{
    const value=structuredClone(input);
    for(const service of ['firestore','storage']){
      const sections=Array.isArray(value[service])?value[service]:[value[service]];
      for(const section of sections){if(!section)continue;for(const key of ['rules','indexes'])if(section[key])section[key]=await copyFile(section[key],base);}
    }
    const codebases=Array.isArray(value.functions)?value.functions:[value.functions];
    for(const codebase of codebases)if(codebase?.source)codebase.source=await copySource(codebase.source,base);
    for(const emulator of Object.values(value.emulators??{}))if(emulator&&typeof emulator==='object'){emulator.host='127.0.0.1';emulator.port=0;}
    const path=join(baseline,'firebase.json');
    await writeFile(path,JSON.stringify(value),{mode:0o600});
    // Storage target associations require the original project's alias file.
    try{await cp(join(base,'.firebaserc'),join(baseline,'.firebaserc'));}catch(error){if(error.code!=='ENOENT')throw error;}
    return path;
  };
  let input=options.config??{schemaVersion:1};
  let configBase=cwd;
  if(typeof input==='string'){const path=resolve(cwd,input);input=await readConfiguration(path,options);configBase=dirname(path);}
  let config;
  if(input.schemaVersion===undefined){config={schemaVersion:1,firebaseJson:await snapshotFirebase(input,configBase)};}
  else{
    config=structuredClone(input);
    if(config.firebaseJson){const path=resolve(configBase,config.firebaseJson);config.firebaseJson=await snapshotFirebase(JSON.parse(await readFile(path,'utf8')),dirname(path));}
    for(const [section,key] of [['rules','source'],['firestore','indexFile'],['firestore','textIndexDefinitionFile'],['storage','rules'],['functions','manifest']]){
      if(config[section]?.[key])config[section][key]=await copyFile(config[section][key],cwd);
    }
    if(config.functions?.source)config.functions.source=await copySource(config.functions.source,cwd);
  }
  if(options.firebaseJson){const path=resolve(cwd,options.firebaseJson);config.firebaseJson=await snapshotFirebase(JSON.parse(await readFile(path,'utf8')),dirname(path));}
  if(options.functionsSource){config.functions??={};config.functions.source=await copySource(options.functionsSource,cwd);}
  const functionsConfigured=Boolean(graph.size||config.functions?.manifest||config.functions?.runner);
  const nodePaths=[];
  for(const entry of (functionsConfigured?options.env?.NODE_PATH??'':'').split(delimiter).filter(Boolean)){
    let original=resolve(cwd,entry);
    try{
      try{original=await realpath(original);}catch(error){if(error.code==='ENOENT')continue;throw error;}
      let destination=graph.get(original);
      if(!destination){
        destination=join(baseline,`node-path-${sequence++}`,'node_modules');
        await captureTree(original,destination,nodePathExcludes.map(name=>join(original,name)));
      }
      nodePaths.push(destination);
    }catch(cause){
      throw Error(`Cannot snapshot NODE_PATH entry ${JSON.stringify(entry)} (copy root ${JSON.stringify(original)}): ${cause.message}. If this global package is unused, exclude its name with nodePathExcludes; if all global roots are unused, set env.NODE_PATH to an empty string`,{cause});
    }
  }
  config.daemon={...config.daemon,clockStart:options.clockStart??config.daemon?.clockStart??'2026-01-01T00:00:00Z',seed:options.seed??config.daemon?.seed??1,authProject:options.projectId??config.daemon?.authProject??'demo-test-world'};
  for(const service of ['firestore','http','storage','functions','eventarc','tasks','pubsub','database','hub','ui','logging'])config.daemon[`${service}Port`]=0;
  config.functions={...config.functions,clock:{date:'virtual',timers:'real',tasks:'virtual',...config.functions?.clock,...options.clock}};
  await writeFile(join(baseline,'fireemu.json'),JSON.stringify(config),{mode:0o600});
  let seed;
  if(options.import){seed=join(baseline,'seed');await cp(resolve(cwd,options.import),seed,{recursive:true,mode:constants.COPYFILE_FICLONE,dereference:true});}
  return {baseline,config,seed,nodePaths,functionsConfigured};
}

export async function prepareGeneration(snapshot,directory){
  await mkdir(directory,{mode:0o700});
  const inputs=join(directory,'inputs');
  await cp(snapshot.baseline,inputs,{recursive:true,mode:constants.COPYFILE_FICLONE,dereference:false,verbatimSymlinks:true});
  const rewrite=value=>typeof value==='string'&&value.startsWith(`${snapshot.baseline}${sep}`)?`${inputs}${value.slice(snapshot.baseline.length)}`:Array.isArray(value)?value.map(rewrite):value&&typeof value==='object'?Object.fromEntries(Object.entries(value).map(([key,item])=>[key,rewrite(item)])):value;
  // Windows junctions are absolute; copying them verbatim would expose the baseline.
  const relocateLinks=async path=>{
    for(const entry of await readdir(path,{withFileTypes:true})){
      const child=join(path,entry.name);
      if(entry.isSymbolicLink()){
        const target=await readlink(child);
        const relocated=rewrite(target);
        if(relocated!==target){
          const kind=(await lstat(target)).isDirectory()?'dir':'file';
          await unlink(child);
          await symlink(relocated,child,process.platform==='win32'&&kind==='dir'?'junction':kind);
        }
      }else if(entry.isDirectory())await relocateLinks(child);
    }
  };
  await relocateLinks(inputs);
  const config=rewrite(snapshot.config);
  if(config.firebaseJson){const firebase=rewrite(JSON.parse(await readFile(config.firebaseJson,'utf8')));await writeFile(config.firebaseJson,JSON.stringify(firebase),{mode:0o600});}
  await writeFile(join(inputs,'fireemu.json'),JSON.stringify(config),{mode:0o600});
  await mkdir(join(directory,'tmp'),{mode:0o700});
  return {configPath:join(inputs,'fireemu.json'),cwd:inputs,seed:snapshot.seed?rewrite(snapshot.seed):undefined,nodePath:(snapshot.nodePaths??[]).map(rewrite).join(delimiter)};
}
