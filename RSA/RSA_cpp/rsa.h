#include<iostream>
#include<random>
#include<vector>
#define ll long long
using namespace std;

struct message{
    ll *m;
};

class RSA{

    //Data structure required for the RSA algorithm.
    private:
        // privateKey contains two primes p, q and the d which is the inverse of the public key.
        struct privateKey{
            ll *p = nullptr;
            ll *q = nullptr;
            ll *phi = nullptr;  // (p-1)(q-1)
            ll *d = nullptr;
        };
        privateKey * pk = nullptr;

        // cipheredMessage contains the encrypted message.
        struct cipheredMessage{
            ll *c = nullptr;
        };
    
    public:
        // n is the multiplication factor of two prime numbers.
        ll *n = nullptr;

        // public key contains n and e a random number.
        struct publicKey{
            ll *n = nullptr;
            ll *e = nullptr;
        };
        publicKey * pb = nullptr;
    
    private:
        ll getRandom();
        ll mod(ll i, ll * base);
        ll pow(ll base, ll exp);
        pair<bool, ll> extendedEuclidean(ll r1, ll r2, ll s1, ll s2);
        pair<ll, ll> getKeys();
        void keyGeneration();
        message* decrypt(cipheredMessage* C);

    public:
        RSA();
        RSA(ll, ll);
        bool isPrime(ll x);
        cipheredMessage * encrypt(message * M);
        message* decryptBackdoor(cipheredMessage * C);
        
};


// getRandom generates a random value.
ll RSA::getRandom(){
    random_device  rd;
    uniform_int_distribution<long long> dist(2, LONG_LONG_MAX);
    long long r1 = dist(rd);
    return r1;
}

// mod performs the modulo operation in base.
ll RSA::mod(ll i, ll * base){
    if( i >= 0) return i%(*base);
    ll r = i % (*base);
    return (*base) + r;
}

// pow calculates the power of base raised to exp.
ll RSA::pow(ll base, ll exp){
    ll res = 1;
    while(exp > 0){
        if(exp % 2 == 1) res = mod(res * base, pb->n);
        base = mod(base * base, pb->n);
        exp /= 2;
    }
    return mod(res, pb->n);
}

// extendedEuclidean find the gcd anf the inverse.
pair<bool, ll> RSA::extendedEuclidean(ll r1, ll r2, ll s1, ll s2){
    if( r2 == 1 ){
        return make_pair(true, mod(s2, pk->phi));
    }
    if (r2 > r1){
        long long t = r2; r2 = r1; r1 = t;
        return extendedEuclidean(r1, r2, s1, s2);
    }
    if(r2 == 0){
        cout<<"Error: unexpected error\n";
        exit(1);
    }
    
    ll q = r1/r2, r = r1%r2;
    if(r == 0) {
        return make_pair(false, 0);
    }
    return extendedEuclidean(r2, r, s2, s1 - q*s2);
}

// getKeys finds the pair of co-prime numbers e and d such that e*d = 1 (mod phi).
pair<ll, ll> RSA::getKeys(){
    vector< pair<ll, ll>> arr;
    for( ll i = 1; i < *pk->phi; i++){
        pair<bool,ll> k = extendedEuclidean(*pk->phi, i, 0, 1);
        if(k.first == true){
            arr.push_back(make_pair(i, k.second));
        }
    }
    if ( arr.size() == 0 ){
        throw runtime_error("No keys found.");
    }
    ll randIndex = getRandom() % arr.size();
    return arr[randIndex];
}

bool RSA::isPrime(ll x){
    if ( x <= 1 )   return false; 
    for( ll i = 2; i < sqrt(x); i++){
        if( x % i == 0 )    return false;
    }
    return true;
}

// keyGeneration sets the public key and private key.
void RSA::keyGeneration(){ 
    RSA::pk = new RSA::privateKey;
    pk->p = new ll(getRandom());
    pk->q = new ll(getRandom());
    cout<<*pk->p<<" "<<*pk->q<<endl;
    RSA::n = new ll(*(pk->p) * *(pk->q));
    ll phi = (*pk->p - 1) * (*pk->q - 1);
    pk->phi = new ll(phi);
    pair<ll, ll> t = getKeys();

    pk->d = new ll(t.second);
    pb = new RSA::publicKey;
    pb->n = n;
    pb->e = new ll(t.first);

}

// decrypt deciphers the encrypted message.
message* RSA::decrypt(cipheredMessage* C){
    message * M = new message;
    M->m = new ll(pow(*(C->c), *(pk->d)));
    cout<<"Deciphered message: "<<*M->m<<endl;
    return M;
}

// RSA constructor generates the public and private keys using random function.
RSA::RSA() {
    keyGeneration();
    cout<<"Public key: "<<*pb->e<<" "<<*pb->n<<endl;
    cout<<"Private key: "<<*pk->d<<" "<<*pk->p<<" "<<*pk->q<<" "<<*pk->phi<<endl;
}

// RSA constructor accepts the two prime numbers p and q as parameters and sets the private key.
RSA::RSA(ll p, ll q){
    if ( !isPrime(p) || !isPrime(q) ){
        throw logic_error("Invalid prime numbers.");
    }
    RSA::pk = new RSA::privateKey;

    pk->p = new ll(p);
    pk->q = new ll(q);
    RSA::n = new ll(*(pk->p) * *(pk->q));
    ll phi = (*pk->p - 1) * (*pk->q - 1);
    pk->phi = new ll(phi);
    pair<ll, ll> t = getKeys();
    pk->d = new ll(t.second);
    pb = new RSA::publicKey;
    pb->n = n;
    pb->e = new ll(t.first);
    cout<<"Public key: "<<*pb->e<<" "<<*pb->n<<endl;
    cout<<"Private key: "<<*pk->d<<" "<<*pk->p<<" "<<*pk->q<<" "<<*pk->phi<<endl;
}

// encrypt creates a ciphered message.
RSA::cipheredMessage * RSA::encrypt(message * M){
    cipheredMessage *C = new cipheredMessage;
    C->c = new ll(pow(*(M->m), *(pb->e)));
    cout<<"Ciphered message is: "<<*C->c<<endl;
    return C;
}

// decryptBackdoor decrypts the encrypted message using the backdoor key.
message* RSA::decryptBackdoor(cipheredMessage * C){
    return decrypt(C);
}