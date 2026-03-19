/**
 * Sets the document title. Resets to default on unmount.
 */

import { useEffect } from 'react';

const SUFFIX = 'AkesoDLP';

export default function useTitle(page: string) {
  useEffect(() => {
    document.title = `${page} | ${SUFFIX}`;
    return () => {
      document.title = SUFFIX;
    };
  }, [page]);
}
