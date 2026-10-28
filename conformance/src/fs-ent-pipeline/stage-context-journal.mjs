import { closeSync, fsyncSync, openSync, writeSync } from 'node:fs';

// No reopen or append: an uncertain run remains spent and requires reviewed recovery.
export function createStageJournal(path, secret) {
  if (typeof secret !== 'string' || secret.length === 0) throw new Error('journal secret guard required');
  const fd=openSync(path,'wx',0o600);
  let closed=false;
  return {
    async write(event) {
      if(closed)throw new Error('journal closed');
      const line=JSON.stringify(event);
      if(line.includes(secret) || line.includes(Buffer.from(secret).toString('base64'))) throw new Error('secret in journal');
      const bytes=Buffer.from(line+'\n');
      let offset=0;
      while(offset<bytes.length) {const n=writeSync(fd,bytes,offset,bytes.length-offset);if(n<=0)throw new Error('journal short write');offset+=n;}
      fsyncSync(fd);
    },
    close() {if(!closed){closed=true;closeSync(fd);}},
  };
}
