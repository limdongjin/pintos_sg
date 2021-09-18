#include <stdio.h>
#include <syscall.h>
#include <stdlib.h>

// ./additional [num1] [num2] [num3] [num4]
// stdout> fibonacci(num1) max_of_four_int(num1, num2, num3, num4)
int
main (int argc, char **argv)
{
   int n1, n2, n3, n4;
   int ret1, ret2;

   if(argc != 5){
     printf("Usage : ./additional [num 1] [num 2] [num 3] [num 4]\n");
     printf("please check Usage\n");
     return 0;
   }

   n1=atoi(argv[1]);
   n2=atoi(argv[2]); 
   n3=atoi(argv[3]);
   n4=atoi(argv[4]);
   
   if(n1 < 0 || n1 > 46){
     ret1 = -1;
     printf("fibonacci(n) : supported 0 <= n <= 46..\n");
   }else{
    ret1 = fibonacci(n1);
   }

   ret2 = max_of_four_int(n1, n2, n3, n4);
   printf("%d %d\n", ret1, ret2);
   
   return EXIT_SUCCESS;
}
