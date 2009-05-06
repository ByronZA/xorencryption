/*****************************************************
 * cbc.c 
   
   This is a simple xor chain encryption program that will encrypt a
     file, the filename of which must be provided as a command line
     argument, using a simple CBC encryption algorithm.  Upon
     execution of the program, the user is prompted to enter a
     password.  If the file is not encrypted, the file will be
     overwritten with the encrypted file, and a hash of the password
     will be prepended to the begining of the file.  If the file is
     encrypted, the password is checked against this embedded hash
     value before decrypting and overwriting the file.  

   The target file is cached in RAM; the amount of RAM necessary is
     double the size of the file.
 *
 ****************************************************/
#include <stdio.h>

int stringsize(char* string) {
  int i = 0;
  while ( *(string + i++) != (char) NULL);
  return  i-1;
}

int clearstring(char* string) {
  int i = 0;
  if (string == NULL)
    return 0;
  while ( *(string + i) != (char) NULL) {
    *(string + i) = ' ';
    i++;
  }
  return 1;
}

int strip_extra_space( char* p1, char* p2) {
  int j;
  int i;
  char c;
  char lastc;
  i = 0;
  j = 0;
  do {
    c = *(p1 + i );
    if (c == ' ' && lastc == ' ') {
      i++;
      continue;
    }
    *(p2 + j) = c;
    lastc = c;
    j++;
    i++;
  } while ( c != (char) NULL);
  return j;

}

int readfile(char* f, int size, FILE* ifile) {
  fseek(ifile,0,SEEK_SET);
  fread(f, 1, size, ifile);
  *(f + size) = (char) NULL;
  fclose(ifile);
  return 0;
}  

int writefile(char* f, int size, char* filename) {
  FILE* ofile;
  ofile = fopen(filename,"w");
  if (ofile==NULL) {
    printf("error writing file\n");
    return 1;
  } else {
    fwrite(f,1, size, ofile);
    fclose(ofile);
  }
  return 0;
}

int stripp(char* p1, char* p2, int psize) {  /* take out vowels from the passwd */
  int j,i;
  char c;
  j=0;
  for (i=0;i<psize;i++) {
    c = *(p1 + i);
    if ( c == ' ' || c == 'a' || c == 'e' || c == 'i' || c == 'o' || c == 'u') {
      ;}
    else 
      *(p2+j++) = c;
  }
  return j;
} 

int getline(char*s , int lim) {  /* gets password from keyboard */
  char*t;
  int c;
  int len;
  len = lim;
  t=s;
  while (--lim>1 && (c=getchar()) != EOF && c != '\n')
    *s++ = c;
  if (c == '\n')
    *s++ = c;
  else if (lim == 1) {
    *s++ = '\n';
    fprintf(stderr, "warning, getline too long. splited.\n");
  }
  *s = '\0';
  return s - t;
}


int file_is_encrypted_probably (char* f, int fsize) { /*not implemented */
  int i;
  int cnt;
  char c;
  float percent;
  cnt = 0;
  for (i=0;i<fsize;i++) {
    c = *(f + i);
    if ((c >= 'a' && c <='z') || (c >= 'A' && c <= 'Z') || (c == ' ') || (c>='1' && c <= '9') || (c=='(') || (c==')') || (c=='*') || (c=='=') || (c==';') || (c=='{') || (c=='}'))
      cnt++;
  }
  percent = (float) ((float)cnt/(float)fsize);
  printf("\npercentage=%f",percent);
  if (percent >= .666)
    return 0;
  else
    return 1;
}

void fillstring(char* s, int size, char c) {
  int i;
  for (i=0;i<size;i++) 
    *(s + i)=c;
  return;
}

int decrypt(char* f1, char* f2, int filesize, char* p2, int p2size) {
  char c;
  char f;
  int i;
  int j;
  char p;
  char* constant;
  char cons;
  constant = (char*) malloc (sizeof(char) * (p2size + 1));
  if (constant==NULL)
    return 1;
  fillstring(constant,p2size,'0');
  for (i=0;i<filesize;i++) {
    f = *(f1 + i);
    j = i % p2size;
    p = *(p2 + j);
    cons = *(constant + j);
    c = p ^ f ^ cons;
    *(f2 + i) = c;
    *(constant + j) = c;
  }
  *(f2 + i) = (char) NULL;
  free(constant);
  return 0;
}

int encrypt(char* f1, char* f2, int filesize, char* p2, int p2size) {
  char c;
  char f;
  int i;
  int j;
  char p;
  char* constant;
  char cons;
  constant = (char*) malloc (sizeof(char) * (p2size + 1));
  if (constant == NULL)
    return 1;
  fillstring(constant,p2size,'0');
  for (i=0;i<filesize;i++) {
    f = *(f1 + i);
    j = i % p2size;
    p = *(p2 + j);
    cons = *(constant + j);
    c = p ^ f ^ cons;
    *(f2 + i) = c;
    *(constant + j) = f;
  }
  *(f2 + i) = (char) NULL;
  free(constant);
  return 0;
}



int getheaderendpos(char* f, int filesize) {  /* used in the event of variable sized headers */
  int i;
  for (i=0;i<filesize -4;i++)
    if (*(f+i)== 0 && (char) *(f+i +1)== 'h' && (char) *(f+ i+2)== 'v' && *(f+ i +3) == 0)
      return i+4;
  return 0;
}

void writeheader(char* f, long hash) {
  long* hashptr;
  hashptr = (long*) f;
  *hashptr = hash;
  f[6] = 0;
  f[7] = 'h';
  f[8] = 'v';
  f[9] = 0;
  f[10] = 'x';              /* the 'x' at position 10 means this cbc algorithm was used*/
  return;
}

static long hash(const char *key) {

  int i=0;
  long mask=0x0fffffff;
  long hashvalue=0;
  int downshift=1 ;

  while (*key != '\0')
    i=(i<<3)+(*key++ - '0');
  hashvalue = (((i*1103515249)>>downshift) & mask);
  if (hashvalue < 0) {
    hashvalue = 0;
  }    
   return hashvalue;

}


long get_hashfile(char* f)
{
  long* hash;
  hash = (long*) f;
  return *hash;

}



int main(int argc, char** argv) {
  FILE* ifile;
  char* p1;                            /* contains password */
  char* p2;                            /* contains stripped password */
  char* f1;                            /* cache of input file */
  char* f2;                            /* cache of file to be written */
  char* fileread;                      /* ptr into string of f1 */
  char* filewrite;                     /* ptr into string of f2 */
  int filesize;
  int filesizetarget;
  int filebegining;
  int fileend;
  int file_is_encrypted;
  int p1size;
  int p2size;
  int encrypted;
  int errchk;
  long hashfile;
  long hashp2;
  int headerend;
  int stdhdrsize;
  stdhdrsize = 20;
  hashfile = 0;
  p1 = (char*) NULL;
  p2 = (char*) NULL;
  f1 = (char*) NULL;
  encrypted = 0;
  if (argc != 2) {
    printf("\nRequires a filename argument to encrypt or decrypt\n");
    return 1;
  }
  ifile = fopen((char*)argv[1],"r");
  if (ifile==NULL) {
    printf("\nUnable to open file %s\n", argv[1]);
    return 1;
  }
  fseek(ifile,0,SEEK_SET);                 /* get filesize */
  filebegining= ftell(ifile);
  fseek(ifile,0,SEEK_END);
  fileend = ftell(ifile);
  filesize= fileend - filebegining;
  
  p1 = (char*) malloc(sizeof(char)*666);
  if (p1 == NULL) {
    printf("\nFailed to allocate memory");
    return 1;
  }
  printf("\nEnter Encryption Key:");
  getline(p1,666);  
  if (*p1 == (char) NULL) {
    printf("%s","\nRequires encryption key\n");
    free(p1);
    return 1;
  }
  p1size = stringsize(p1);
 
  p2 = (char*) malloc (sizeof(char) * (p1size + 1));
  if (p2==NULL) {
    printf("\nFailed to allocate memory");
    free(p1);
    return 1;
  }
  p2size = stripp(p1,p2,p1size); 
  clearstring(p1);
  free(p1);

 if (p2size<2) {
    printf("Password must contain more consonants\n");
    free(p2);
    return 1;
 }
  hashp2 = hash(p2);
  f1 = (char*) malloc (sizeof(char) * (filesize + 2 + stdhdrsize));
  if (f1==NULL) {
    printf("\nFailed to allocate memory");
    free(p2);
    return 1;
  }
  f2 = (char*) malloc (sizeof(char) * (filesize + 2 + stdhdrsize));
  if (f2==NULL) {
    printf("\nFailed to allocate memory");
    free(f1);
    free(p2);
    return 1;
  }
  readfile(f1,filesize,ifile);
  headerend = getheaderendpos(f1, filesize - 1);

  if (headerend == 0) {
    file_is_encrypted = 0;
    fileread = (char*) f1;
    filewrite = (char*) (f2 + stdhdrsize);
  } else {
    file_is_encrypted = 1;
    filewrite = f2;
    fileread = (char*) (f1 + stdhdrsize);
    hashfile = get_hashfile(f1);
 
    if (hashfile != hashp2 ) {
      printf("the password is not valid, please try again\n");
      clearstring(p2);
      free(p2);
      free(f1);
      free(f2);
      return 1;
    }
    if (f1[10]!='x') {
      printf("wrong decryption algorithm\n");
      clearstring(p2);
      free(p2);
      free(f1);
      free(f2);
      return 1;
    }
}
  p2size--;
  if ( file_is_encrypted) {
    printf("\nXOR chain decryption applied to this file: %s\n", argv[1]);
    errchk =  decrypt(fileread,filewrite,filesize,p2,p2size);
    filesizetarget = filesize - stdhdrsize;
}  else {
    printf("\nXOR chain encryption applied to this file: %s\n", argv[1]);
    errchk =  encrypt(fileread,filewrite,filesize,p2,p2size);
    writeheader(f2,hashp2);
    filesizetarget = filesize + stdhdrsize;
}

  if (errchk == 0)
    writefile(f2,filesizetarget,(char*)argv[1]);
  else
    printf("\nFailed to allocate memory");
  clearstring(p2);
  clearstring(f1);
  clearstring(f2);
  free(p2);
  free(f1);
  free(f2);
  printf("\n");
  return 0;
}
