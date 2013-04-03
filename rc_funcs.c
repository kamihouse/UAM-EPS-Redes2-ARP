/***************************************************************************
 * Include : rc_funcs                 Versión : 4.0.0     FECHA : 08/feb/07
 *
 * Descripcion :
 *   Funciones auxiliares para practicas de Redes de Comunicaciones
 *
 * Fecha : 14/jul/00
 * Autor : Sergio Lopez y Antonio Martinez
 * Centro: UAM - EPS
 *
 * Cambios:
 *   * 05/dic/00. V2.0.1. Antonio Martinez
 *      - Cambiado tipo de datos del mensaje en calcula_crc a BYTE * para
 *        consistencia con tipos de level1.
 *   * 20/sep/02: V3.0.0. Antonio Martinez
 *      - Adaptado a los nuevos nombres de funciones de la interfaz nivel1
 *   * 08/feb/07: V4.0.0 Manuel Freire
 *      - Eliminada 'ObtenerDirDestino'
 *      - Incorporada lee_cadena_ip (hace casi lo mismo) y lee_cadena_eth
 *      - Eliminados acentos
 *      - Modificado prototipo de calcula_crc para simplificar su uso
 *   * 07/mar/07: V4.0.1 Jose Hernandez & Manuel Freire
 *      - Incorporado calcula_checksum_ip
 ***************************************************************************/
/* Copyright */
const char * CPYR_ETHD = "(C) Copyright S. Lopez, A. Martinez, M. Freire, 2000-2002-2007. rc_funcs.o V.4.0.0";
/***************************************************************************/

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "ip.h"
#include "rc_funcs.h"

/*************************************************************************
 * Funcion: CalculaCRC
 * Fecha: 15.09.1998
 * Autor: Sergio Lopez
 *
 * Descripción
 *  Funcion generica para el calculo del CRC de una secuencia de
 *  bits, suponiendo que el primer bit es el menos significativo
 *  de mensaje[0] y que el ultimo bit es el mas significativo de
 *  mensaje[longitud-1]. De igual manera, en el resultado el bit
 *  menos significativo es el primero del CRC.
 *
 *  polinomio[i] debe ser igual al coeficiente del termino de
 *  grado i del polinomio generador, para todos los terminos
 *  MENOS el de mayor grado.
 *
 *  Ej.: el polinomio generador del CCITT es 1 + x5 + x12 + x16
 *       char plinomio[] = {1,0,0,0,0,1,0,0,0,0,0,0,1,0,0,0};
 *
 * Entrada:
 *    unsigned longitud: Longitud del mensaje
 *    BYTE *mensaje: Mensaje del que se debe calcular el CRC
 *    BYTE *crc: Destino del CRC (2 bytes)
 * Salida:
 *    nada, y el 'crc' actualizado
 *************************************************************************/
void calcula_crc(unsigned longitud, BYTE *mensaje, BYTE *crc)
{
   /* polinomio generador */
   char polinomio[] = {1,0,0,0,0,1,0,0,0,0,0,0,1,0,0,0};

   /* variables */
   unsigned long resultado = -1;
   char ctl;
   int i,j,k;

   /* bucle principal para el calculo del CRC */
   for(i = 0; i < longitud; i++)
   {
      for(j = 0; j < 8; j++)
      {
         ctl = (resultado & 1) ^ ((mensaje[i] >> j) & 1);
         resultado = (resultado & ~1) >> 1;

         for(k = 0; k < sizeof(polinomio); k++)
         {
           if(ctl && polinomio[sizeof(polinomio) - 1 - k])
              resultado ^= (unsigned long) 1 << k;
         }
      }
   }

   /* pone a cero los bits del resultado no ocupados por el CRC          */
   for(i = sizeof(polinomio); i < sizeof(resultado) * 8; i++)
          resultado |= (unsigned long) 1 << i;

   /* devuelve el CRC de la secuencia                                    */
   resultado = ~resultado;
   resultado >>= 16;
   crc[0] = resultado & 0xff;
   crc[1] = (resultado >> 8) & 0xff;
}

/***************************************************************************
 * Obtiene un checksum tipo IP a partir de un conjunto de bytes
 * entra:
 *   longitud - n. bytes de los datos sobre los que calcular el checksum
 *   datos - datos sobre los que calcular el checksum
 *   checksum - checksum de los datos (2 bytes)
 * sale:
 *   nada
 ***************************************************************************/
void calcula_checksum_ip(unsigned longitud, BYTE *datos, BYTE *checksum) {
    unsigned int word16;
    unsigned long sum=0;
    int i;
    
    // make 16 bit words out of every two adjacent 8 bit words in the packet
    // and add them up
    for (i=0; i<longitud; i=i+2){
        word16 = (datos[i]<<8) + datos[i+1];
        sum += (unsigned long)word16;       
    }
    
    // take only 16 bits out of the 32 bit sum and add up the carries
    while (sum>>16) {
        sum = (sum & 0xFFFF)+(sum >> 16);
    }

    // one's complement the result
    sum = ~sum;
        
    checksum[0] = sum >> 8;
    checksum[1] = sum & 0xFF;
    return;
}

/****************************************************************************
 * Convierte una cadena de texto a una direccion Ethernet
 * entra:
 *   dir - una direccion en formato aa:bb:cc:dd:ee:ff
 *   eth - puntero a un BYTE[ETH_ALEN] donde escribir la dir. Ethernet obtenida
 * sale:
 *   -1 si error, 0 si todo bien (y la dir Ethernet bien copiada)
 ****************************************************************************/
int lee_cadena_eth(char *texto, BYTE *dir_eth) {
  int i;
  int tmp[ETH_ALEN];

  if ( ! texto)
  {
    fprintf(stderr, "Dir. 'NULL' no definida.\n");
    return(-1);
  }  
  
  if (sscanf(texto, "%2x:%2x:%2x:%2x:%2x:%2x", 
        tmp+0, tmp+1, tmp+2, tmp+3, tmp+4, tmp+5) != 6) {        
      fprintf(stderr, "- Dir. Ethernet '%s' no tiene formato 'aa:bb:cc:dd:ee:ff'\n", texto);
      return(-1);
  } 
  for (i=0; i<ETH_ALEN; i++) {
    dir_eth[i] = tmp[i];
  }
  return 0;
}

/****************************************************************************
 * Convierte una cadena de texto a una direccion IP
 * entra:
 *   dir - una direccion en formato aaa.bbb.ccc.ddd
 *   ip - puntero a un BYTE[IP_ALEN] donde escribir la direccion IP obtenida
 * sale:
 *   -1 si error, 0 si todo bien (y la dir. IP bien copiada)
 ****************************************************************************/
int lee_cadena_ip(char *texto, BYTE *dir_ip) {
  int  i, b;
  char tmp[IP_ALEN][4];

  if ( ! texto)
  {
    printf("Dir. IP 'NULL' no definida.\n");
    return(-1);
  }  
  
  if (sscanf(texto, "%3[0-9].%3[0-9].%3[0-9].%3[0-9]", 
        tmp[0], tmp[1], tmp[2], tmp[3]) != 4) {
      printf("- Dir. IP '%s' no tiene formato 'aaa.bbb.ccc.ddd'\n", texto);
      return(-1);
  } 
  for (i=0; i<4; i++) {
    b = atoi(tmp[i]);
    if (b > 255 || b < 0) {
        printf("Partes de la dir IP > 255 o < 0.\n");
        return(-1);
    } 
    dir_ip[i] = b;
  }    
  return 0;
}
