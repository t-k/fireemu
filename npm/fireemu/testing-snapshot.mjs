// Snapshot caller-owned input once; each generation gets its own writable copy.
import { constants as fsConstants, createReadStream, createWriteStream } from 'node:fs';
import { mkdir, open, readFile, writeFile, realpath, symlink, lstat, stat, unlink, readdir, readlink, chmod, rm } from 'node:fs/promises';
import { pipeline } from 'node:stream/promises';
import { basename, dirname, join, resolve, relative, sep, delimiter, isAbsolute } from 'node:path';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { resolveBinary, ensureExecutable } from './binary.mjs';

const runFile = promisify(execFile);

function checkSignal(signal){signal?.throwIfAborted();}

function retainCleanupError(error,cleanupError){
  if(error&&typeof error==='object')try{error.cleanupError=cleanupError;}catch{}
}

export async function readRegularFile(path,signal,openFile=open){
  const flags=fsConstants.O_RDONLY|(fsConstants.O_NONBLOCK??0);
  checkSignal(signal);
  const handle=await openFile(path,flags);
  try{
    checkSignal(signal);
    const info=await checked(signal,()=>handle.stat());
    if(!info.isFile())throw Error(`configuration input must be a regular file: ${JSON.stringify(path)}`);
    return await checked(signal,()=>handle.readFile({encoding:'utf8',signal}));
  }finally{await handle.close();}
}

export async function removeSnapshotTree(root){
  const makeWritable=async(path,knownInfo)=>{
    let info=knownInfo;
    try{info??=await lstat(path);}catch(error){if(error.code==='ENOENT')return;throw error;}
    if(!info.isDirectory()||info.isSymbolicLink())return;
    await chmod(path,0o700);
    for(const entry of await readdir(path,{withFileTypes:true})){
      if(entry.isDirectory())await makeWritable(join(path,entry.name));
    }
  };
  try{await makeWritable(root);}catch(error){if(error.code!=='ENOENT')throw error;}
  await rm(root,{recursive:true,force:true});
}

async function checked(signal,operation){
  checkSignal(signal);
  const value=await operation();
  checkSignal(signal);
  return value;
}

async function restoreDirectoryModes(directories,signal){
  try{
    for(const [path,mode] of directories)await checked(signal,()=>chmod(path,mode));
  }catch(error){
    await Promise.all(directories.map(([path])=>chmod(path,0o700).catch(()=>{})));
    throw error;
  }
}

async function copyInputTree(source,destination,{signal,dereference=true,filter,directoryModes}={}){
  const directories=[];
  const visit=async(input,output,ancestors=new Set())=>{
    checkSignal(signal);
    if(filter&&!await checked(signal,()=>filter(input)))return;
    let info=await checked(signal,()=>lstat(input));
    if(info.isSymbolicLink()){
      if(!dereference){
        const value=await checked(signal,()=>readlink(input));
        const kind=process.platform==='win32'?(await checked(signal,()=>stat(input))).isDirectory()?'junction':'file':undefined;
        await checked(signal,()=>mkdir(dirname(output),{recursive:true,mode:0o700}));
        await checked(signal,()=>symlink(value,output,kind));
        return;
      }
      const canonical=await checked(signal,()=>realpath(input));
      if(ancestors.has(canonical))throw Error(`Cannot copy cyclic dependency link ${JSON.stringify(input)}`);
      info=await checked(signal,()=>stat(canonical));
      input=canonical;
    }
    if(info.isDirectory()){
      await checked(signal,()=>mkdir(output,{recursive:true,mode:0o700}));
      const entries=await checked(signal,()=>readdir(input,{withFileTypes:true}));
      const nextAncestors=new Set(ancestors);
      if(dereference){
        const canonical=await checked(signal,()=>realpath(input));
        if(nextAncestors.has(canonical))throw Error(`Cannot copy cyclic dependency directory ${JSON.stringify(input)}`);
        nextAncestors.add(canonical);
      }
      for(const entry of entries){
        checkSignal(signal);
        await visit(join(input,entry.name),join(output,entry.name),nextAncestors);
      }
      directories.push([output,info.mode&0o7777]);
      return;
    }
    if(!info.isFile())throw Error(`Cannot copy unsupported non-regular input ${JSON.stringify(input)}`);
    await checked(signal,()=>mkdir(dirname(output),{recursive:true,mode:0o700}));
    const inputStream=createReadStream(input,{signal});
    const outputStream=createWriteStream(output,{flags:'wx',mode:info.mode&0o777});
    try{
      await pipeline(inputStream,outputStream,{signal});
      checkSignal(signal);
      await checked(signal,()=>chmod(output,info.mode&0o777));
    }catch(error){
      await rm(output,{force:true}).catch(()=>{});
      throw error;
    }
  };
  await visit(source,destination);
  if(directoryModes)directoryModes.push(...directories);
  else await restoreDirectoryModes(directories,signal);
}

async function readConfiguration(path, options, signal) {
  const format = path.toLowerCase().endsWith('.toml') ? 'TOML' : 'JSON';
  try {
    if (format === 'JSON') return JSON.parse(await readRegularFile(path,signal));
    const binary = resolveBinary(options.binaryPath ? resolve(options.binaryPath) : undefined);
    if (!binary) throw Error('install the fireemu platform package or supply binaryPath');
    ensureExecutable(binary.path);
    // Use the CLI parser so TOML types and rejection rules cannot drift between callers.
    const { stdout } = await runFile(binary.path, ['__test-world-config', path], {
      encoding: 'utf8', windowsHide: true, timeout: options.snapshotTimeoutMs ?? 60_000,
      killSignal: 'SIGKILL', maxBuffer: 16 * 1024 * 1024, signal,
    });
    return JSON.parse(stdout);
  } catch (cause) {
    throw Error(`Cannot read ${format} configuration ${JSON.stringify(path)}: ${cause.stderr?.trim() || cause.message}`, { cause });
  }
}

export async function snapshotInputs(options, root, signal=options.signal) {
  checkSignal(signal);
  const cwd=resolve(options.cwd??process.cwd());
  const nodePathExcludes=options.nodePathExcludes===undefined?[]:options.nodePathExcludes;
  const packageName=value=>{
    if(typeof value!=='string'||value.includes('\\')||value.includes('\0'))return false;
    const parts=value.split('/');
    return (value.startsWith('@')?parts.length===2&&parts[0].length>1:parts.length===1)
      &&parts.every((part,index)=>part!=='.'&&part!=='..'&&/^[a-zA-Z0-9._~-]+$/.test(index===0&&value.startsWith('@')?part.slice(1):part));
  };
  if(!Array.isArray(nodePathExcludes)||!nodePathExcludes.every(packageName))throw TypeError('nodePathExcludes must be an array of unscoped or scoped package names');
  const privateRoot=await checked(signal,()=>realpath(root));
  const baseline=join(root,'baseline');
  await checked(signal,()=>mkdir(baseline,{mode:0o700}));
  let sequence=0;
  const directoryModes=[];
  const copyFile=async(value,base)=>{
    if(typeof value!=='string')return value;
    const destination=join(baseline,`input-${sequence++}-${basename(value)}`);
    await copyInputTree(resolve(base,value),destination,{signal,dereference:true,directoryModes});
    return destination;
  };
  const graph=new Map();
  const inside=(parent,path)=>{const suffix=relative(parent,path);return suffix===''||(!suffix.startsWith(`..${sep}`)&&suffix!=='..'&&!isAbsolute(suffix));};
  const omitted=new Set();
  const captureTree=async(source,destination,excludes=[])=>{
    try{
      const canonical=await checked(signal,()=>realpath(source));
      graph.set(canonical,destination);
      const links=[];
      await copyInputTree(canonical,destination,{signal,dereference:false,directoryModes,filter:async(path)=>{
        if(excludes.includes(path)){omitted.add(path);return false;}
        if(['.git','.worktree'].includes(basename(path)))return false;
        if((await checked(signal,()=>lstat(path))).isSymbolicLink())links.push([path,join(destination,relative(canonical,path))]);
        return true;
      }});
      for(const [sourceLink,targetLink] of links){
        let linkValue;
        try{
          linkValue=await checked(signal,()=>readlink(sourceLink));
          const target=await checked(signal,()=>realpath(sourceLink));
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
          await checked(signal,()=>unlink(targetLink));
          const kind=(await checked(signal,()=>lstat(target))).isDirectory()?'dir':'file';
          await checked(signal,()=>symlink(process.platform==='win32'?copied:relative(dirname(targetLink),copied),targetLink,process.platform==='win32'&&kind==='dir'?'junction':kind));
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
    const source=await checked(signal,()=>realpath(resolve(base,value)));
    if(inside(source,privateRoot))throw Error('world temporary directory must be outside the Functions source');
    const dependencies=[];
    for(let ancestor=dirname(source),level=1;;ancestor=dirname(ancestor),level++){
      const modules=join(ancestor,'node_modules');
      try{if((await checked(signal,()=>stat(modules))).isDirectory())dependencies.push({modules,level});}catch(error){if(error.code!=='ENOENT')throw error;}
      if(dirname(ancestor)===ancestor)break;
    }
    const container=join(baseline,`functions-${sequence++}`);
    const depth=dependencies.at(-1)?.level??0;
    const destination=join(container,...Array(depth).fill('source'));
    await captureTree(source,destination);
    for(const {modules,level} of dependencies){
      let ancestor=destination;for(let count=0;count<level;count++)ancestor=dirname(ancestor);
      const target=join(ancestor,'node_modules'),canonical=await checked(signal,()=>realpath(modules));
      if(graph.has(canonical))await checked(signal,()=>symlink(process.platform==='win32'?graph.get(canonical):relative(ancestor,graph.get(canonical)),target,process.platform==='win32'?'junction':'dir'));
      else await captureTree(modules,target);
    }
    return destination;
  };
  const snapshotFirebase=async(input,base)=>{
    checkSignal(signal);
    const value=structuredClone(input);
    for(const service of ['firestore','storage']){
      const sections=Array.isArray(value[service])?value[service]:[value[service]];
      for(const section of sections){if(!section)continue;for(const key of ['rules','indexes'])if(section[key])section[key]=await copyFile(section[key],base);}
    }
    const codebases=Array.isArray(value.functions)?value.functions:[value.functions];
    for(const codebase of codebases)if(codebase?.source)codebase.source=await copySource(codebase.source,base);
    for(const emulator of Object.values(value.emulators??{}))if(emulator&&typeof emulator==='object'){emulator.host='127.0.0.1';emulator.port=0;}
    const path=join(baseline,'firebase.json');
    await checked(signal,()=>writeFile(path,JSON.stringify(value),{mode:0o600}));
    // Storage target associations require the original project's alias file.
    await checked(signal,()=>rm(join(baseline,'.firebaserc'),{force:true}));
    try{await copyInputTree(join(base,'.firebaserc'),join(baseline,'.firebaserc'),{signal,directoryModes});}catch(error){if(error.code!=='ENOENT')throw error;}
    return path;
  };
  let input=options.config??{schemaVersion:1};
  let configBase=cwd;
  if(typeof input==='string'){const path=resolve(cwd,input);input=await readConfiguration(path,options,signal);configBase=dirname(path);}
  let config;
  if(input.schemaVersion===undefined){config={schemaVersion:1,firebaseJson:await snapshotFirebase(input,configBase)};}
  else{
    config=structuredClone(input);
    if(config.firebaseJson){const path=resolve(configBase,config.firebaseJson);config.firebaseJson=await snapshotFirebase(JSON.parse(await readRegularFile(path,signal)),dirname(path));}
    for(const [section,key] of [['rules','source'],['firestore','indexFile'],['firestore','textIndexDefinitionFile'],['storage','rules'],['functions','manifest']]){
      if(config[section]?.[key])config[section][key]=await copyFile(config[section][key],cwd);
    }
    if(config.functions?.source)config.functions.source=await copySource(config.functions.source,cwd);
  }
  if(options.firebaseJson){const path=resolve(cwd,options.firebaseJson);config.firebaseJson=await snapshotFirebase(JSON.parse(await readRegularFile(path,signal)),dirname(path));}
  if(options.functionsSource){config.functions??={};config.functions.source=await copySource(options.functionsSource,cwd);}
  const functionsConfigured=Boolean(graph.size||config.functions?.manifest||config.functions?.runner);
  const nodePaths=[];
  for(const entry of (functionsConfigured?options.env?.NODE_PATH??'':'').split(delimiter).filter(Boolean)){
    let original=resolve(cwd,entry);
    try{
      try{original=await checked(signal,()=>realpath(original));}catch(error){if(error.code==='ENOENT')continue;throw error;}
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
  await checked(signal,()=>writeFile(join(baseline,'fireemu.json'),JSON.stringify(config),{mode:0o600}));
  let seed;
  if(options.import){seed=join(baseline,'seed');await copyInputTree(resolve(cwd,options.import),seed,{signal,dereference:true,directoryModes});}
  await restoreDirectoryModes(directoryModes,signal);
  return {baseline,config,seed,nodePaths,functionsConfigured};
}

async function prepareGenerationInputs(snapshot,directory,signal){
  const inputs=join(directory,'inputs');
  const directoryModes=[];
  await copyInputTree(snapshot.baseline,inputs,{signal,dereference:false,directoryModes});
  const rewrite=value=>typeof value==='string'&&value.startsWith(`${snapshot.baseline}${sep}`)?`${inputs}${value.slice(snapshot.baseline.length)}`:Array.isArray(value)?value.map(rewrite):value&&typeof value==='object'?Object.fromEntries(Object.entries(value).map(([key,item])=>[key,rewrite(item)])):value;
  // Windows junctions are absolute; copying them verbatim would expose the baseline.
  const relocateLinks=async path=>{
    for(const entry of await checked(signal,()=>readdir(path,{withFileTypes:true}))){
      checkSignal(signal);
      const child=join(path,entry.name);
      if(entry.isSymbolicLink()){
        const target=await checked(signal,()=>readlink(child));
        const relocated=rewrite(target);
        if(relocated!==target){
          const kind=(await checked(signal,()=>lstat(target))).isDirectory()?'dir':'file';
          await checked(signal,()=>unlink(child));
          await checked(signal,()=>symlink(relocated,child,process.platform==='win32'&&kind==='dir'?'junction':kind));
        }
      }else if(entry.isDirectory())await relocateLinks(child);
    }
  };
  await relocateLinks(inputs);
  const config=rewrite(snapshot.config);
  if(config.firebaseJson){const firebase=rewrite(JSON.parse(await checked(signal,()=>readFile(config.firebaseJson,'utf8'))));await checked(signal,()=>writeFile(config.firebaseJson,JSON.stringify(firebase),{mode:0o600}));}
  await checked(signal,()=>writeFile(join(inputs,'fireemu.json'),JSON.stringify(config),{mode:0o600}));
  await checked(signal,()=>mkdir(join(directory,'tmp'),{mode:0o700}));
  await restoreDirectoryModes(directoryModes,signal);
  return {configPath:join(inputs,'fireemu.json'),cwd:inputs,seed:snapshot.seed?rewrite(snapshot.seed):undefined,nodePath:(snapshot.nodePaths??[]).map(rewrite).join(delimiter)};
}

export async function prepareGeneration(snapshot,directory,signal){
  let owned=false;
  try{
    checkSignal(signal);
    await mkdir(directory,{mode:0o700});
    owned=true;
    checkSignal(signal);
    return await prepareGenerationInputs(snapshot,directory,signal);
  }catch(error){if(owned)try{await removeSnapshotTree(directory);}catch(cleanupError){retainCleanupError(error,cleanupError);}throw error;}
}
