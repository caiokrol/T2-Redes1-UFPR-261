#include <core.p4>
#if __TARGET_TOFINO__ == 3
#include <t3na.p4>
#elif __TARGET_TOFINO__ == 2
#include <t2na.p4>
#else
#include <tna.p4>
#endif

#include "headers.p4"
#include "parser.p4"


/* ===================================================== Ingress ===================================================== */


control SwitchIngress(
    /* User */
    inout header_t      hdr,
    inout metadata_t    meta,
    /* Intrinsic */
    in ingress_intrinsic_metadata_t                     ig_intr_md,
    in ingress_intrinsic_metadata_from_parser_t         ig_prsr_md,
    inout ingress_intrinsic_metadata_for_deparser_t     ig_dprsr_md,
    inout ingress_intrinsic_metadata_for_tm_t           ig_tm_md)
{
    /* Forward */
    action hit(PortId_t port) {
        ig_tm_md.ucast_egress_port = port;
    }

    action miss(bit<3> drop) {
        ig_dprsr_md.drop_ctl = drop;
    }

    table forward {
        key = {
            hdr.ethernet.dst_addr : exact;
        }

        actions = {
            hit;
            @defaultonly miss;
        }

        const default_action = miss(0x1);
        size = 1024;
    }

    /* 
    Cria um registrador no formato:
        Register <tipo de dado armazenado, tamanho do indexador> (quantas entradas)
    No caso abaixo cria um registrador com uma entrada, indexado por 1 bit e valores de 32 bits.
    DICA: o mesmo registrador não pode ser acessado mais de uma vez por pacote, e armazenam valores
    de no máximo 32 bits, utilize multiplos registradores
    */
    Register<bit<32>, bit<1>> (1) reg_token_P1;
    Register<bit<32>, bit<1>> (1) reg_token_P2;
    Register<bit<32>, bit<1>> (1) reg_token_P3;
    Register<bit<32>, bit<1>> (1) reg_token_P4;

    apply {
        /* Realiza roteamento MAC. Não excluir */
        forward.apply();

        /*
        Para ler um registrador:
            secret_values.read(index);

        Para escrever:
            secret_values.write(index, value);

        Para dropar um pacote:
            ig_dprsr_md.drop_ctl = 1;
        */


        if(hdr.token.isValid()){ //1. Usa a funçao nativa do P4 pra ver se um cabeçalho é valido com nosso cabeçalho
            
            if(hdr.token.msg_type == 8w0x1){ //2. Pacote chegando pra guardar o token no switch
                reg_token_P1.write(0, hdr.token.token[127:96]); //Seçao 8.6 manual do P4 disponibilizado para fatiar o linguicao de bits
                reg_token_P2.write(0, hdr.token.token[95:64]);
                reg_token_P3.write(0, hdr.token.token[63:32]);
                reg_token_P4.write(0, hdr.token.token[31:0]);

                ig_dprsr_md.drop_ctl = 1; //É só o token chegando entao morre aqui no switch
            }

            else if(hdr.token.msg_type == 8w0x2){ //3. Pacote tentando passar pelo tunel
                meta.aux1 = reg_token_P1.read(0);
                meta.aux2 = reg_token_P2.read(0);
                meta.aux3 = reg_token_P3.read(0);
                meta.aux4 = reg_token_P4.read(0);

                    if( hdr.token.token[127:96] != meta.aux1 || 
                        hdr.token.token[95:64] != meta.aux2 ||
                        hdr.token.token[63:32] != meta.aux3 ||
                        hdr.token.token[31:0] != meta.aux4)
                    {
                        ig_dprsr_md.drop_ctl = 1; //Acesso negado (Dropa o pacote porque nao bateu o token, se nao passa normalmente)
                    }
            }

            else {
                ig_dprsr_md.drop_ctl = 1; //4.Nao entendeu o tipo da mensagem entao dropou (Provavel lixo ou erro no pacote)
            }

        } else {
            ig_dprsr_md.drop_ctl = 1; // 5.Dropa se nao for valido a leitura do cabeçalho
        }

    }
}

/* ===================================================== Egress ===================================================== */

control SwitchEgress(
    /* User */
    inout header_t      hdr,
    inout metadata_t    meta,
    /* Intrinsic */
    in egress_intrinsic_metadata_t                      eg_intr_md,
    in egress_intrinsic_metadata_from_parser_t          eg_prsr_md,
    inout egress_intrinsic_metadata_for_deparser_t      eg_dprsr_md,
    inout egress_intrinsic_metadata_for_output_port_t   eg_oport_md)
{
    apply {}
}


/* ===================================================== Final Pipeline ===================================================== */
Pipeline(
    SwitchIngressParser(),
    SwitchIngress(),
    SwitchIngressDeparser(),
    SwitchEgressParser(),
    SwitchEgress(),
    SwitchEgressDeparser()
) pipe;

Switch(pipe) main;
