#include<cstdlib>
#include<iostream>
#include "ecc.h"
int main(){
    ecc e = ecc(11,1,6);

    message *m = new message;
    m->x = 2; m->y = 4;
    cryptedMessage *C = e.encrypt(m);
    cout<<"Ciphered Text Message\n";
    cout<<"C1: ("<<C->C1->x<<", "<<C->C1->y<<")\n";
    cout<<"C2: ("<<C->C2->x<<", "<<C->C2->y<<")\n";

    message *m2 = e.decrypt_backdoor(C);
    cout<<"Decrypted Message: ("<<m2->x<<", "<<m2->y<<")\n";
    delete m; delete C; delete m2;
    return 0;
}