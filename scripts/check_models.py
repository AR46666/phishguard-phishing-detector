import os
import joblib
import pickle
import numpy as np

MODELS_DIR = os.path.join(os.path.dirname(__file__), '..', 'models')

def hexdump(path, n=64):
    with open(path, 'rb') as f:
        data = f.read(n)
    return data


def inspect_file(path):
    print('---')
    print('File:', path)
    try:
        size = os.path.getsize(path)
        print('Size:', size, 'bytes')
    except Exception as e:
        print('Could not get size:', e)
        return

    try:
        head = hexdump(path, 128)
        print('First bytes:', head[:64])
    except Exception as e:
        print('Could not read head:', e)

    # Try joblib.load
    try:
        obj = joblib.load(path)
        print('joblib.load: SUCCESS, type:', type(obj))
        return
    except Exception as e:
        print('joblib.load ERROR:', repr(e))

    # Try pickle.load
    try:
        with open(path, 'rb') as f:
            obj = pickle.load(f)
        print('pickle.load: SUCCESS, type:', type(obj))
        return
    except Exception as e:
        print('pickle.load ERROR:', repr(e))

    # Try numpy load (npz)
    try:
        arr = np.load(path, allow_pickle=True)
        print('numpy.load: SUCCESS, type:', type(arr))
        return
    except Exception as e:
        print('numpy.load ERROR:', repr(e))

    print('No loader succeeded for this file.')


if __name__ == '__main__':
    print('Inspecting models directory:', MODELS_DIR)
    if not os.path.isdir(MODELS_DIR):
        print('Models directory not found.')
    else:
        for fname in os.listdir(MODELS_DIR):
            fpath = os.path.join(MODELS_DIR, fname)
            if os.path.isfile(fpath):
                inspect_file(fpath)
