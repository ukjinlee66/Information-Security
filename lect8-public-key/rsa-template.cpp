#include <stdio.h>
#include <math.h>

int enc(int M, int e, int n);
int dec(int C, int d, int n);
int compute_pow(int a, int b, int m);
int select_e(int phi1);
int compute_phi2(int phi1);
int GCD(int a, int b);
char prime[500000];

int main() 
{
	for (int i=2;i<500001;i++)
		prime[i] = 1;
	for (int n = 2; n <= floor(sqrt(500000)); n++)
	{
		if (!prime[n]) continue;
		for (int mult = 2; n * mult <= 500000; mult++)
			prime[n * mult] = 0;
	}

	printf("enter p and q, two prime numbers\n");
	int p, q;
	scanf("%d %d", &p, &q);
          // step 1. compute n
	int n = p * q;
         // step 2. compute phi1
	int phi1 = (p - 1) * (q - 1);
	
	int e; int phi2; int d;

	for (;;) {
                   // step 3. select e 
		e = select_e(phi1);
                   // step 4. compute phi2
		phi2 = compute_phi2(phi1);

                   // step 5. compute d
		d = compute_pow(e, phi2 - 1, phi1);
		if (e == d) {
			printf("not suitable e. select another one\n");
		}
		else {
			printf("(%d %d) are ok to use ", e, d); break;
		}
	}
	printf("p:%d q:%d n:%d phi1:%d e:%d phi2:%d d:%d\n",
		p, q, n, phi1, e, phi2, d);
	// now encrypt
	printf("enter num to encrypt\n");
	int M, C;
	scanf("%d", &M);
	C = enc(M, e, n);
	printf("M:%d C:%d\n", M, C);
	int Mp = dec(C, d, n);
	printf("Mp:%d\n", Mp);
}
int enc(int M, int e, int n) {
	return compute_pow(M, e, n);
}
int dec(int C, int d, int n) {
	return compute_pow(C, d, n);
}
int compute_pow(int a, int b, int m) {
	//return a^b mod m
	int p;
	int a1;

	a1 = a % m;
	p = 1;
	for (int i = 1; i <= b; i++)
	{
		p *= a1;
		p = p % m;
	}
	return (p);
}

int select_e(int phi1) {
// display relative prime numbers to phi1 
// let user select one of them
          // display relative prime numbers to phi1
	for(int i=1;i<phi1;i++)
		if (prime[i])
			printf("%d ",i);
          // let user select one of them
	printf("\nselect one of these: ");
	int e;
	scanf("%d", &e);
	return e;
}
int compute_phi2(int phi1) {
	// return num of relative prime numbers to phi1
	int cnt = 0;
	for(int i=1;i<phi1;i++)
		if (GCD(i, phi1) == 1) cnt++;
	return (cnt);
}
int GCD(int a, int b) {
	// return GCD of a, b
	int t;
	for (;;)
	{
		if (b == 0) break;
		t = b;
		b = a % b;
		a = t;
	}
	return (a);
}
