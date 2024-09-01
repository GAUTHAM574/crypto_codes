#include<iostream>
#include "rsa.h"
using namespace std;


int main() {
    RSA *rsa = new RSA(10007, 10009);
    message* m = new message;
    m->m = new ll(5);
    rsa->decryptBackdoor(rsa->encrypt(m));
    return 0;
}