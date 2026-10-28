export async function capturePriorityCase(io,item){
 let observer,writer,result,error;
 try{
  observer=await io.openObserver(item);await observer.watch();writer=await io.openWriter(item);await writer.register(item);await writer.offline();
  if(await writer.waitClosed()!==true)throw Error('writer close unknown');
  const capture=await io.capture(observer,item);if(capture?.observed!==true)throw Error('observer capture unknown');
  const readback=await observer.readback();if(!readback||!Object.hasOwn(readback,'s')||!Object.hasOwn(readback,'t'))throw Error('readback unknown');
  result={acknowledged:true,writerClosed:true,observed:true,readback,capture};
 }catch(e){error=e;}
 for(const resource of [writer,observer])if(resource){try{await resource.close();}catch(e){error??=e;}}
 if(error)throw error;return result;
}
