  /***************************************************************************
 * arpt.c
 *
 *  Programa principal para probar ARP en las practicas de 
 *  Redes de Comunicaciones 2 de la EPS-UAM
 *
 *  Autor: Manuel Freire
 *
 *  (C) 2006-07 EPS-UAM 
 ***************************************************************************/

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <signal.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/wait.h>

#include "nivel1.h"
#include "rc_funcs.h"
#include "arp.h"

#define MAX_LINEA 256 
 
/****************************************************************************
 * Procesa tramas Ethernet entrantes desde el nivel1
 * Copia la trama y, si es procesable, la procesa
 *
 * entra:
 *    tamano - en bytes de toda la trama, incluyendo cabeceras ethernet
 *    trama - los bytes de la trama
 * sale:
 *    0 si todo bien, -1 si error en el procesamiento
 ****************************************************************************/
#ifdef _ETHD_VERSION_4_1_0
int gestiona_trama_ethernet(int tamano, const BYTE *trama) {
#else
int gestiona_trama_ethernet(int tamano, const BYTE *trama,struct timeval *tv) {
#endif
    BYTE buffer[ETH_FRAME_MAX];
    
    /*
     * 'recibe' la trama oficialmente de nivel1, realizando una copia.
     * NOTA: nivel1 nunca llama a esta funcion de forma reentrante, porque 
     *   gestiona la recepcion de tramas segun llegan en un unico hilo
     */
	
	
#ifdef _ETHD_VERSION_4_1_0
    if (RecibirTramaNivel1(buffer) != tamano) {
#else
    if (RecibirTramaNivel1(buffer,NULL) != tamano) {
#endif
        fprintf(stderr, "Error: fallo en nivel1 recibiendo trama\n");
        return -1;
    }    
    
    // comprueba si es una trama ARP, y en caso afirmativo, la procesa
    if (tamano == ETH_FRAME_MIN && 
        memcmp(ethertype_arp, buffer+ETH_ALEN+ETH_ALEN, ETH_TLEN) == 0) {        
        
        arp_inicializa();
        arp_procesa_trama(tamano, buffer, buffer+ETH_ALEN);
    }
        
    return 0;
}

/***************************************************************************
 * "main"
 ***************************************************************************/
int main(int argc, char **argv)
{
  char buffer[MAX_LINEA];
  BYTE dir_ip[IP_ALEN];
  BYTE dir_eth[ETH_ALEN];
  int debug = 0;
  int fin_solicitado = 0;
  int rc;
  
  char *ayuda =
    "Uso: arpt [<nivel_trazas>]\n"
    "  <nivel_trazas> - 0 = sin trazas, 3 = maximo detalle\n";
        
  char *teclas = 
    "Usa:\n"
    "  'a' - enviar una peticion\n"
    "  'c' - mostrar la tabla ARP\n"
    "  'q' - salir\n";    
  
  // trazas
  if (argc > 1) {
    debug = atoi(argv[1]);
    if (argv[1][0] < '0' || argv[1][0] > '9' || debug < 0 || debug > 3) {
        fprintf(stderr, ayuda);
    }
  }
  ActivarTrazas(debug, "stdout");

  // inicia el nivel1; no usa 'timeout' para la recepcion
  if (IniciarNivel1(1, ethertype_arp, gestiona_trama_ethernet, 0) != ETH_OK) {
    fprintf(stderr, "Error en IniciarNivel1\n");
    return -1;
  }
  if (arp_inicializa() != 0) {
    fprintf(stderr, "Error en arp_inicializa\n");
    FinalizarNivel1();
    return -1;
  }  

  // bucle principal
  printf("ARP-T iniciado; usa 'h' para ver la ayuda.\n");
  while ( ! fin_solicitado) {
    if (fgets(buffer, MAX_LINEA, stdin) == NULL) {
        fin_solicitado = 1;
    }
    else {
        switch (buffer[0]) {
            case 'a': case 'A':
                if (lee_cadena_ip(buffer+2, dir_ip) != -1) {
                    rc = arp_solicita_direccion(dir_ip, dir_eth);
                    if (rc == -1) {
                        printf("- Direccion Ethernet. no encontrada.\n");
                    }
                    else {
                        printf("- Direccion Ethernet. encontrada: "
                            "%2.2x:%2.2x:%2.2x:%2.2x:%2.2x:%2.2x\n", 
                            dir_eth[0], dir_eth[1], dir_eth[2],
                            dir_eth[3], dir_eth[4], dir_eth[5]);
                    }
                }
                else {
                    printf("Dir. IP mal escrita; vuelve a intentarlo.\n");
                }
                break;
            case 'c': case 'C':
                arp_muestra_cache();
                break;
            case 'q': case 'Q': case -1:
                fin_solicitado = 1;    
                break;
            case 'h': case 'H':
                printf(teclas);
                break;
            case '\n':
                break;
            default:
                printf("No entiendo '%s'. %s", buffer, teclas);
                break;
        }
    }
  }

  // salida limpia (Ctrl+C tambien funciona, pero esto es mas bonito)
  if (FinalizarNivel1() != ETH_OK) {
    printf("Error en FinalizarNivel1, rc = %d \n",rc);
    return -1;
  }

  return 0;
}
