export async function capturePriorityCase(io,item){
 let observer,writer,result,error;
 try{
  observer=await io.openObserver(item);await observer.watch();await observer.assertLive();writer=await io.openWriter(item);await writer.register(item);await writer.offline();
  if(await writer.waitClosed()!==true)throw Error('writer close unknown');
  await observer.assertLive();const capture=await io.capture(observer,item);await observer.assertLive();if(capture?.observed!==true)throw Error('observer capture unknown');
  await observer.assertLive();const readback=await observer.readback();await observer.assertLive();if(!readback||!Object.hasOwn(readback,'s')||!Object.hasOwn(readback,'t'))throw Error('readback unknown');
  result={acknowledged:true,writerClosed:true,observed:true,readback,capture};
 }catch(e){error=e;}
 for(const resource of [writer,observer])if(resource){try{await resource.close();}catch(e){error??=e;}}
 if(error)throw error;return result;
}
