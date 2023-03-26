from .common import *
from .keys import *
from .ctr_tik import tikReader
from .ctr_tmd import TMDReader

class CDNReader:
    def __init__(self, content_files, tmd, tik='', dev=0):
        content_files.sort(key=lambda h: int(h.split('.')[0], 16))
        self.content_files = content_files
        self.tmd = tmd
        self.tik = tik
        self.dev = dev
        self.tmd_read = TMDReader(tmd, dev)

        if tik != '': # If ticket is present, parse ticket to get titlekey
            self.tik_read = tikReader(tik, dev)
            self.titlekey = self.tik_read.titlekey
        else: # Use titlekey generation algorithm
            self.titlekey = hextobytes(CTR.titlekey_gen(self.tmd_read.titleID, 'mypass'))
        
    def decrypt(self):
        for i in self.content_files:
            for name, info in self.tmd_read.files.items():
                if name.split('.')[1] == i: # CDN files are named as contentID
                    f = open(i, 'rb')
                    g = open(name, 'wb')
                    cipher = AES.new(self.titlekey, AES.MODE_CBC, iv=info['iv'])
                    for data in read_chunks(f, info['size']):
                        g.write(cipher.decrypt(data))
                    f.close()
                    g.close()
                    print(f'Decrypted {i} to {name}')
                    break
    
    def verify(self):
        tmd = self.tmd_read.verify(no_print=1)
        hash_check = tmd[0]
        for i in self.content_files:
            for name, info in self.tmd_read.files.items():
                if name.split('.')[1] == i:
                    f = open(i, 'rb')
                    name2 = '.'.join(name.split('.')[:-1]) # Remove extension so printout is short enough to be aligned
                    h = hashlib.sha256()
                    cipher = AES.new(self.titlekey, AES.MODE_CBC, iv=info['iv'])
                    for data in read_chunks(f, info['size']):
                        h.update(cipher.decrypt(data))
                    f.close()
                    hash_check.append((name2, h.digest() == info['hash']))
                    break

        sig_check = []
        if self.tik != '':
            sig_check += self.tik_read.verify(no_print=1)
        sig_check += tmd[1]

        print('Hashes:')
        for i in hash_check:
            print(' > {0:15} {1:4}'.format(i[0] + ':', 'GOOD' if i[1] else 'FAIL'))
        print('Signatures:')
        for i in sig_check:
            print(' > {0:15} {1:4}'.format(i[0] + ':', 'GOOD' if i[1] else 'FAIL'))

    def __str__(self):
        if self.tik != '':
            tik = 'Ticket:\n' + ''.join(['  ' + i + '\n' for i in self.tik_read.__str__().split('\n')])
        else:
            tik = ''
        tmd = ''.join(['  ' + i + '\n' for i in self.tmd_read.__str__().split('\n')])
        return (
            f'{tik}'
            f'TMD:\n'
            f'{tmd[:-1]}' # Remove last '\n'
        )

class CDNBuilder:
    def __init__(self, content_files=[], tik='', tmd='', dev=0, out_tik='tik_new'):
        '''
        content_files: list containing filenames of content files, which must each be named '[content index in hex, 4 chars].[contentID in hex, 8 chars].[ncch/nds]'
        Certificate chain will be appended at the end of the following files:
            - tik: path to ticket (optional)
            - tmd: path to tmd
        dev: 0 or 1 (if 1, use dev-crypto for ticket titlekey)
        out_tik: path to output ticket with cert chain appended
        '''
        
        content_files.sort(key=lambda h: int(h.split('.')[0], 16))
        self.content_files = content_files
        self.tmd = tmd
        self.tik = tik
        self.dev = dev
        self.tmd_read = TMDReader(tmd, dev)

        if tik != '': # If ticket is present, parse ticket to get titlekey
            self.tik_read = tikReader(tik, dev)
            self.titlekey = self.tik_read.titlekey
        else: # Use titlekey generation algorithm
            self.titlekey = hextobytes(CTR.titlekey_gen(self.tmd_read.titleID, 'mypass'))
        
        # Encrypt content files
        for i in self.content_files:
            info = self.tmd_read.files[i]
            name = i.split('.')[1] # CDN files are named as contentID
            f = open(i, 'rb')
            g = open(name, 'wb')
            cipher = AES.new(self.titlekey, AES.MODE_CBC, iv=info['iv'])
            for data in read_chunks(f, info['size']):
                g.write(cipher.encrypt(data))
            f.close()
            g.close()
            print(f'Wrote to {name}')

        # Append certificate chain to end of tmd (and tik)
        name = f'tmd.{self.tmd_read.hdr.title_ver}'
        with open(name, 'wb') as f:
            with open(tmd, 'rb') as g:
                f.write(g.read())
            if dev == 0:
                with open(os.path.join(resources_dir, 'CP0000000b.cert'), 'rb') as g:
                    f.write(g.read())
                with open(os.path.join(resources_dir, 'CA00000003.cert'), 'rb') as g:
                    f.write(g.read())
            elif dev == 1:
                with open(os.path.join(resources_dir, 'CP0000000a.cert'), 'rb') as g:
                    f.write(g.read())
                with open(os.path.join(resources_dir, 'CA00000004.cert'), 'rb') as g:
                    f.write(g.read())
            print(f'Wrote to {name}')
        
        if self.tik != '':
            with open(f'{out_tik}', 'wb') as f:
                with open(tik, 'rb') as g:
                    f.write(g.read())
                if dev == 0:
                    with open(os.path.join(resources_dir, 'XS0000000c.cert'), 'rb') as g:
                        f.write(g.read())
                    with open(os.path.join(resources_dir, 'CA00000003.cert'), 'rb') as g:
                        f.write(g.read())
                elif dev == 1:
                    with open(os.path.join(resources_dir, 'XS00000009.cert'), 'rb') as g:
                        f.write(g.read())
                    with open(os.path.join(resources_dir, 'CA00000004.cert'), 'rb') as g:
                        f.write(g.read())
            print(f'Wrote to {out_tik}')
