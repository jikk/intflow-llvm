/*
 * =====================================================================================
 *
 *       Filename:  warning.c
 *
 *    Description:  
 *
 *        Version:  1.0
 *        Created:  06/11/2013 01:43:09 PM
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  YOUR NAME (), 
 *   Organization:  
 *
 * =====================================================================================
 */
#include <stdio.h>

void lldivWarning(long long int denom)
{
        if (denom == 0)
                fprintf(stderr, "Warning: lldiv() called with denominator of value zero");
}
