import itertools
import csv
from math import log
import Kyber
#from MLWE_security import MLWE_summarize_attacks, MLWEParameterSet

# parameter set
q_value = [3329, 7681]
k_value = [3, 4]
eta_value = range(2, 6) # 2-5
du_bit_length = range(10, 13) # 10-12
dv_bit_length = range(10, 13) # 10-12

# csv setting
with open('kyber_test_results.csv', mode='w', newline='') as csvfile:
    field_name = ['n', 'k', 'q', 'eta_1', 'eta_2', 'du', 'dv', 'DFR',
                  'CS', 'QS', 'Pk', 'CT']
    writer = csv.DictWriter(csvfile, field_name)
    writer.writeheader()

    # start testing 
    for q, k, eta_1, eta_2, du_bits, dv_bits in itertools.product(q_value, k_value,
                                                                  eta_value, eta_value,
                                                                  du_bit_length, dv_bit_length,
                                                                  ):
        du = 2**du_bits
        dv = 2**dv_bits
        bits_of_q = 12 if q == 3329 else 13

        # set up each kyber parameter
        tmp_ps = Kyber.KyberParameterSet(
                n=256,
                m=k,
                ks=eta_1,
                ke=eta_1,
                q=q,
                rqk=2**bits_of_q,
                rqc=du,
                rq2=dv,
                ke_ct=eta_2
                )
        
        print ("Kyber (modified):")
        print ("--------------------")
        print ("security:")
        Primal_res = Kyber.MLWE_summarize_attacks(Kyber.Kyber_to_MLWE(tmp_ps))
        Pk, CT, f= Kyber.summarize(tmp_ps)
        f = log(f + 2.**(-300))/log(2)
        print () 
        # write result to CSV file
        writer.writerow({
            'n':256,
            'k':k,
            'q':q,
            'eta_1':eta_1,
            'eta_2':eta_2,
            'du':du_bits,
            'dv':dv_bits,
            'DFR': f,
            'CS': Primal_res[1],
            'QS': Primal_res[2],
            'Pk': Pk,
            'CT': CT
            })
